# Safety, Authorization, And What The System Refuses To Do

## Why this chapter exists

The system described in this briefing is an offensive security tool. It attacks
computer systems on purpose, in order to prove — with evidence anyone can
re-check later — whether a real weakness exists.

That makes it powerful, and power of this kind needs a leash that is not made of
good intentions.

The usual way software tries to keep an AI system under control is to write
instructions into the AI's prompt: "only test authorised targets", "be careful",
"do not be destructive". That approach fails for a simple reason. The AI is
reading text, and an attacker — or a confused page on the target website, or a
typo by the operator — can also write text. If the only thing standing between
the tool and an unauthorised system is a polite instruction, then anyone who can
put words in front of the AI can move that line.

This system takes the opposite approach, and it states the principle in its own
documentation as a slogan: **permission is infrastructure, not prompt.**

In practice that means the AI is never the thing that decides what is allowed.
The AI proposes an action. Separate, small, ordinary programs — with no AI in
them at all — then decide whether that action may happen. Those programs read a
signed authorisation document, check the target against it, check the danger
level of the action, check whether a human has approved it, check whether the
emergency stop has been pulled, and check whether the network is even permitted
to carry the traffic. Only if **every one** of those checks says yes does
anything leave the machine.

An analogy: think of a laboratory that handles dangerous samples. The scientist
inside can ask for anything. But the door has a card reader, the card only works
during booked hours, the ventilation interlock has to be closed, and a second
person has to badge in for the highest-risk work. The scientist's intentions are
not the safety system. The doors are.

This chapter walks through every one of those doors.

It then turns the question round. Sections 1 to 11 are about the system not
harming the customer. Section 12 asks the opposite question — who would attack
this tool, how, and what stops them — and section 13 covers how the product's own
construction is assured, since a security tool is only as trustworthy as the parts
it is built from. Section 14 collects the honest limits in one place, and section
15 lists what an inspector can verify without taking anyone's word for it.

---

## 1. Nothing happens without a written authorisation

### 1.1 The charter

Before the system may touch any target, a document called the **engagement
charter** must exist for that target. It is an ordinary text file, one per
target, kept in the project alongside the work.

It is not a formality. The system reads it, and refuses to proceed without it.

**Two skeletons ship with the system, and the difference matters.** There is a
master template, and there is a shorter starter skeleton that gets copied when a
new target folder is created. Both run to **fifteen numbered sections** plus a
short header block. They are identical except for one thing: the master template
also carries a cloud-scope block, numbered `2b`, and the starter skeleton does
not. The practical consequence is set out after the table.

Here is what each section holds, in plain terms.

| Section | What it records |
|---|---|
| Header | Version number, status (draft or operator-confirmed), and the date it was last changed. |
| 1. Operator attestation | A signed statement by a named person that they are the legal owner (or authorised representative) of the systems listed, that they have the authority to order this testing, and that they authorise it. |
| 2. In-scope systems | A table listing every host and surface that may be touched. Anything not in this table is not authorised. |
| 2b. Cloud scope | A separate table for cloud and container-cluster targets, which are authorised by account identity rather than by web address (explained in section 1.4). **Present in the master template only.** |
| 3. Out of scope (explicit) | Systems that must never be touched even if the tool finds a way to reach them — in particular third parties such as payment processors, identity providers, hosting companies, email and text-message providers, and content delivery networks. |
| 4. Hard limits | Nine things that are never permitted at all. They are set out in full immediately after this table. |
| 5. Test accounts | The dummy accounts the operator has created for the test, all tagged with a common prefix so the operator can find and delete every artefact afterwards. |
| 6. Soft limits | Operating manners: the off-peak window for heavy scanning; a default of five to ten requests being sent at the same time (the tool can send several requests in parallel to work faster, and this caps how many); the instruction to respect the target's own rate limits and back off rather than fight them; notification before heavy scans; a single fixed source internet address so the operator can find the traffic in their own logs; and the identifying label the tool puts on its requests. |
| 7. Posture | Which of three operating modes applies (see section 7.1 of this chapter). |
| 8. Objectives | What a successful engagement would look like, in the operator's own business terms. |
| 9. Stop conditions | The circumstances in which the system must halt and ask: signs the target is degrading, evidence that somebody else already broke in, the discovery that real personal or payment data can be read, any ambiguity about whether something is in scope, or the operator saying stop. |
| 10. Communication plan | Who to contact, on what channel, and how quickly — including a dedicated emergency-stop channel. |
| 11. Source code delivery | Whether the operator will hand over source code for a white-box review. |
| 12. Continuous testing intent | Whether this is one-off or repeated on a cadence. |
| 13. Reporting | Which deliverables are expected. |
| 14. Re-scope and amendments | The rule that any expansion of scope requires the charter to be edited, versioned, dated, logged, and re-confirmed. The template states plainly that the system does not assume an expansion was authorised merely because it seems reasonable. |
| 15. Engagement closure | What has to be true before the engagement is over: every objective addressed, every finding given a final status, every test artefact cleaned up, every credential shared during the work rotated, the reports delivered, and the follow-on testing plan agreed — then signed off by name and date on both sides. |

**What the missing cloud block means in practice.** The part of the code that
decides whether a cloud account may be touched looks for that exact heading —
`## 2b. Cloud scope` — in the signed charter. A charter started from the shorter
skeleton has no such heading, so the answer to "is this cloud account
authorised?" comes back as *nothing is authorised*, and every cloud request is
refused. That is the safe direction, and it is deliberate: leaving the section
out is the documented way to leave cloud testing switched off. But an operator
who expects cloud work to run and copied the shorter skeleton will get refusals
until they add the block by hand. It is a papercut in the starting materials, not
a hole in the enforcement — the failure is toward "no".

**The nine hard limits, in full.** These are the sentences the template puts
under the heading "never violated":

1. No attempt to knock the service over — no flooding it with traffic or
   connections, no deliberate resource exhaustion.
2. No movement of real money beyond a cash cap the operator writes in.
3. No contact with real users: no password-reset emails, no notifications or
   text messages to real customers.
4. No copying of real personal data beyond the minimum needed to demonstrate
   the problem — with a maximum number of records, and redaction in the
   evidence.
5. Nothing left behind on a production system beyond what is needed as proof,
   and that removed within the same session.
6. No attack on a third party.
7. No proxy chains, no Tor, no rotating residential internet addresses (the
   techniques a real intruder uses to make their traffic hard to trace), unless
   the adversary-emulation posture has been explicitly authorised.
8. No bulk deletion of data.
9. No changes to administrator settings on a production system without a fresh,
   explicit confirmation for each change.

### 1.2 How the signature is checked — and why that check is unusually careful

The charter has a line that reads `Signed:` followed by a name. Until a real name
is written there, the charter is unsigned and the system refuses.

The program that checks this is deliberately fussy, because a sloppy check here
would be an authorisation bypass. Two specific tricks are closed off:

- **An empty signature line must not "borrow" the next line.** Text files can end
  a line in several different ways, and the common way of writing this check in
  the industry only recognises one of them. Under the sloppy version, a blank
  `Signed:` line could run on and pick up the following line of the document —
  so a charter with nobody's name on it could be read as "signed by
  `## 2. In-scope systems`". The code isolates the signature line using a method
  that recognises every line ending a human editor can produce, so the value can
  never cross a line break. The project's own notes record that this was a real
  bypass found by an internal adversarial review, not a theoretical one.
- **An invisible signature must not count.** Certain characters look like letters
  to a computer but render as nothing at all on screen. A person reading the
  charter would see a blank line; the naive check would see a signature. The code
  carries the complete list of such characters and rejects them.

### 1.3 The scope table is read literally, and an empty answer means "refuse"

The system reads the in-scope table and extracts the exact host names written
there. Two rules matter:

- If the charter names no in-scope hosts — because the section is missing, or the
  table is malformed, or the heading was written in a different style — the
  result is an **empty list**, and the code treats an empty list as a refusal,
  not as permission. The comment in the code is blunt about the reasoning: an
  authorisation that authorises nothing is not useful, and an empty result
  usually means something upstream is broken. Failing at that point is far safer
  than proceeding on a mystery.
- A target that is not in the list is refused by name, and the refusal message
  prints the scope it was checked against, so the operator can see immediately
  whether the charter or the request was wrong.

There is a real example of this in the project's own history. An earlier charter
used a free-form "Target hosts" heading rather than the numbered
"2. In-scope systems" heading the parser reads. The result was an empty scope,
and the system refused every request — which is exactly the correct behaviour for
a document it could not confidently understand. A later charter carries a note
explaining the format requirement so the next person does not repeat it.

### 1.4 Cloud and container targets are authorised by account, not by address

This is a subtle point with large consequences, and the system gets it right.

Cloud services share addresses. Thousands of unrelated organisations reach Amazon
Web Services through the same public endpoint. If the charter authorised the
*address*, it would in effect authorise everybody's account behind that address —
a catastrophic over-grant.

So the cloud section of the charter authorises a **tenant identity**: the
specific account, project, subscription, or cluster. The rules the code enforces:

- Provider and account are matched **exactly** (case-insensitively).
- A blank entry, a `*`, or the word `any` in either field **authorises nothing**.
  There is no wildcard shortcut.
- Region and resource may optionally be narrowed further; when the charter
  narrows them, a request that does not say which region or resource it wants is
  refused rather than assumed.
- Leaving the section out entirely leaves cloud testing unauthorised.

**Where this stands in practice.** This gate, and the six cloud and
container-cluster confirmations that sit behind it, are built and wired end to
end. Three of the six have been fired at something real, and the three are not of
equal weight: the two container-cluster (Kubernetes) ones against a real Kubernetes
cluster the system stands up, owns and destroys itself, which is real infrastructure
but the project's own; and the GitHub half of the exposed-secret check against the
real GitHub service, the only one of the six to have judged material from a real
outside system. The rest — including that check's Amazon
Web Services half — are proven offline against fixed sample evidence and have
**not** been run against a live cloud account belonging to a third party. That step
needs two things from the customer: their own cloud credentials, and their account
named in the cloud-scope block of a signed charter. Until both exist, the safe
answer the gate gives is "not authorised", which is the correct one. Item 11 in
section 14 states this in full.

### 1.5 A record of who used the tool is created *before* anything runs

Separately from the charter, the system mints a **usage attestation** at the very
start of every engagement. This is a signed record of three things: *who* (the
operating-system login, the configured name and email, a fingerprint of the
operator's key, and the machine name), *when*, and *what* (the action, the
target, the phase of work).

The governing rule, stated in the code and enforced by the engine, is: **no
attestation, no run.** If the record cannot be created — no signer available, the
operator not properly identified, malformed inputs, or the record cannot be
durably written to disk — the engine receives a refusal and the whole engagement
stops before any traffic is generated.

The "when" is deliberately tied to a counter that can only ever go up — supplied
by the machine's security chip when one is present, and by a stored software
counter otherwise. That means a record cannot be back-dated: you cannot quietly
insert an entry claiming a run happened last Tuesday.

Every free-text field in that record is passed through a secret-scrubber before
signing, so a password or token that happened to appear in a command line never
becomes part of a permanent signed record.

### 1.6 The web interface cannot authorise a remote target

The system has a browser-based control panel. It has a Charter screen. That
screen can do exactly one provisioning act: create an authorisation whose scope
is **hard-fixed to the machine's own loopback address** (`127.0.0.1`) — that is,
the operator's own computer talking to itself. "Loopback" is the term for that
special address; a request sent to it never leaves the machine, and no other
computer anywhere can reach it.

For any real remote target, the screen refuses to mint anything. Instead it
*verifies* what already exists and shows the operator the exact command to run —
on a trusted machine that holds the owner's signing key — to create a properly
signed authorisation. The screen displays an advisory "is this target
authorised?" answer computed in the browser, and labels it explicitly as
advisory, with the note that the gate is what actually enforces.

This matters because the browser is the least trustworthy place in the system. A
compromised browser session, or an operator tricked by a malicious web page,
cannot widen the scope of what the tool may attack.

---

## 2. Scope enforcement: how the system refuses, and how it fails safe

Authorisation is checked in several independent places, each of which can only
say "no". A single mistake in one place does not open the door, because the next
place is still closed.

### 2.1 The authorisation gate: six checks, first failure wins

Every action passes through a check sequence. The order is fixed and the code
comments state it plainly:

1. **Has the emergency stop been pulled?** If yes, halt. This is checked before
   anything else.
2. **Are we inside the authorised time window?** Authorisations expire.
3. **Is the target in scope?** If not, refuse.
4. **Is this action destructive, and are destructive actions permitted at all?**
   Default is no.
5. **Is this a destructive action against a live production system, and has the
   operator given the additional, separate acknowledgement required for that?**
   Permission to be destructive in general is deliberately not enough on a live
   system.
6. **Is there budget left?** Every authorisation carries a finite count of
   actions.
7. Only if all six pass is the action allowed.

(A reader who goes to the source file will find the same sequence written out as
seven numbered steps. The seventh is the "allowed" line above, not a seventh
refusal condition. There are six things that can refuse.)

The phrase "fail-closed" appears throughout this codebase, and it has a precise
meaning: if any check cannot be completed — an error, a corrupt file, an
unreadable directory — the answer is **no**, not "carry on". A safety check that
returns "allowed" when it breaks is worse than no check at all, because it
creates false confidence.

The defaults for a new authorisation are conservative: destructive actions off,
an eight-hour validity window, and a finite action budget (the provisioning
command defaults to 1,000 actions).

### 2.2 The traffic guard: the target is resolved once, and the exact address is pinned

Before any request leaves the machine, a second guard checks the destination.

**One piece of vocabulary first, because it recurs.** Every machine on the
internet has a numeric address. There are two formats in use at once. The old,
shorter one — the familiar four numbers such as `127.0.0.1` — is called **IPv4**,
and the world ran out of those addresses years ago. The newer, much longer format
that replaces it is called **IPv6**; the same "this machine talking to itself"
address is written `::1` in that format. Most computers today understand both at
the same time. That matters for safety software for one blunt reason: a check
that covers only the old format leaves a second, fully working door unwatched.
Wherever this chapter says a range is blocked, the code blocks the equivalent
range in both formats.

Its default behaviour, when no signed scope has been supplied, is the strictest
possible: **refuse everything except the machine's own loopback address** — the
address a computer uses to talk to itself, so "loopback only" means "this machine
and nowhere else". Not "allow anything", not "allow the local network" — loopback
only, and in that default mode even the newer IPv6 way of writing loopback is
refused. The code comment states the rule directly: the fail-closed default stays
loopback, never wider.

When a signed authorisation *is* supplied, the guard does something important.
It looks up the target's address **once**, checks every address that lookup
returns against the permanent block list, and then **pins the connection to that
exact address**. It never looks the name up again.

Why this matters: a well-known attack called *DNS rebinding* works by answering
the first address lookup with a harmless public address and the second lookup —
moments later, at the point of connection — with an internal address. A system
that looks up the name, approves it, then looks it up again to connect can be
walked straight into an internal network. Resolving once and pinning the address
closes that gap entirely.

There is a second refinement: if a single name resolves to **several** addresses
and **any one of them** is on the block list, the whole connection is refused.
Refusing on any bad answer defeats a response that deliberately mixes one public
and one internal address hoping the checker will pick the good one.

Anything the guard cannot parse — a malformed address, an impossible port, a name
that will not resolve — is refused. There is no "best effort" branch.

### 2.3 The network floor: a list of addresses that no charter can unlock

Underneath everything sits a list of internet address ranges that are **always**
denied, regardless of what any charter says. The module that holds this list is
described in the code as "the conscience" of the network gate.

The permanently blocked ranges include:

- the machine's own loopback range;
- the "link-local" range that contains **the cloud metadata address**
  (`169.254.169.254`) — the special address that, on a cloud server, hands out
  that server's own credentials to anyone who asks it from inside;
- the reserved documentation and test ranges;
- benchmarking, multicast, and future-use ranges;
- and the equivalent ranges written in the newer IPv6 address format, so the
  same door cannot be walked through in its other spelling.

The reasoning is written into the code and is worth quoting in substance: a
charter **cannot** re-enable these, because a charter listing one of them is far
more likely to be an injection attack or a typing mistake than a genuine
intention to let an autonomous agent read the host machine's cloud credentials.

A separate, *conditional* tier covers private corporate network ranges. Those are
denied **unless** the exact resolved address appears in the charter's authorised
list.

The list also unwraps the disguised forms of an address. There are several
standard ways to write an old-format (IPv4) address inside a new-format (IPv6)
one — the same destination, spelled differently — and a naive checker that only
understands the new format would wave through a disguised metadata address. The
code unwraps each of those spellings and re-checks the result under the old-format
rules.

This module is deliberately "pure": it does no network lookups, reads no files,
and does not consult the clock. The same input always gives the same answer,
which makes it possible to test exhaustively. Both the firewall generator and the
filtering proxy import this one module, so the two enforcement layers cannot
drift apart and start disagreeing.

### 2.4 Two layers of enforcement, one of which the AI cannot argue with

**Layer one — the firewall.** When the agent runs inside its isolated container,
the host machine's firewall drops everything from that container except two
destinations: the system's own filtering proxy and its own name resolver. The
code comment calls this "the layer a prompt-injected agent cannot argue with".
There is no direct route to the internet at all, so an agent that has been
manipulated into unsetting its proxy settings gains nothing — the packets are
dropped at the host. The container is also stripped of the operating-system
privilege that would let it rewrite its own firewall rules. The metadata and
reserved ranges are additionally blocked on the gateway's own outbound path, so
that even a bug in the proxy itself cannot reach them.

One detail shows care about not breaking the operator's machine. The isolated
container is given its own small private address range — a **subnet**, which is
simply a block of neighbouring numeric addresses reserved for one group of
machines, like a single street within a town. The firewall rule picks out only
traffic arriving *from that street* and sends it down a separate **rule chain** —
a named checklist of firewall rules, applied in order — whose final entry is
"refuse". Everything else on the machine, including any unrelated containers the
operator happens to be running, never enters that checklist and is untouched.
Where the system can identify the physical network connection the container is
plugged into, it filters on that instead of on the address, because a program
inside the container can forge the address it claims to be sending from but
cannot forge which wire the packet actually arrived on.

**Layer two — the filtering proxy.** This runs **outside** the sandbox's control.
The contrast the code draws is instructive: the third-party agent tool bundled
with this system ships its own in-sandbox proxy, which the agent itself can
reconfigure or bypass. The system's own proxy cannot be reconfigured from inside,
because it is not inside.

The proxy's configuration is conservative by default: it listens only on the
machine's own loopback interface; it allows only the four normal web ports
(80, 443, 8080, 8443); it gives up on a request whose headers arrive too slowly
(a defence against a class of resource-exhaustion attack); and it caps the number
of simultaneous connections, refusing further ones rather than exhausting the
machine.

Refusals are **logged**, and the code says why: so the operator can correlate them
in their own records. The doctrine is stated as "the agent is correlatable, not
stealthy". That is the opposite of how an intruder behaves, and it is deliberate.

### 2.5 A categorical block list — with an honest note about its wiring

The system contains a module whose sole job is to refuse an entire category of
targets outright, before the charter or any gate is even consulted: government,
military, educational, and intergovernmental organisations.

It works two ways.

**Fourteen address-ending patterns.** A web address ends in a suffix that says
what kind of body owns it. The module refuses `.gov` and its national variants
(`.gov.uk`, `.gob.mx`, `.gouv.fr`, `.govt.nz`, `.go.jp`, `.gv.at`,
`.government.xx`), military endings (`.mil`, `.mil.br`), educational endings
(`.edu`, `.edu.au`, `.ac.uk`), and `.int`, which is reserved for treaty
organisations.

**One hundred and eighty-six named domains.** Many international bodies sit on
ordinary endings such as `.org` and `.eu`, where a suffix rule cannot see them.
So the module also carries an explicit list of exactly 186 named addresses. The
list is grouped in the code, and the groups are these. The counts add up to 186.

| Group | How many | What is in it |
|---|---:|---|
| United Nations core bodies and programmes | 29 | The UN itself and its operational programmes — refugees, children, food, human rights, drugs and crime, and so on. |
| UN regional economic commissions | 5 | The UN's five regional arms: Europe, Asia-Pacific, Africa, Latin America, Western Asia. |
| UN specialised agencies | 8 | The treaty-based agencies: labour, food and agriculture, education and culture, the monetary fund, the World Bank, atomic energy, shipping. |
| International courts and tribunals | 6 | The World Court, the war-crimes tribunals, the law-of-the-sea tribunal, and the African and Inter-American human-rights courts. |
| World Bank group members | 2 | The Bank's private-sector and investment-guarantee arms. |
| European Union institutions | 3 | The EU's own estate, its investment bank, and the European air-traffic organisation. |
| Security and defence organisations | 3 | The European security and co-operation body and the collective-security treaty organisation. |
| Regional intergovernmental organisations | 32 | Regional political unions and blocs across every continent — the African Union, the Association of Southeast Asian Nations, the Organisation of American States, the Commonwealth, the Arab League, and comparable bodies. |
| Development banks and international financial institutions | 21 | The regional development banks (Asian, African, Inter-American, European, Islamic and others) and the financial-action task force. |
| Financial governance and regulation | 2 | The financial stability board and the financial-intelligence group. |
| International trade and commodity organisations | 11 | The World Trade Organisation and the commodity bodies for coffee, cocoa, sugar, olive oil, lead, zinc, nickel and copper. |
| International health bodies | 4 | The vaccine alliance, the global fund, the epidemic-preparedness coalition and the medicines purchasing body. |
| Arms control, non-proliferation and treaty bodies | 10 | The nuclear-test-ban and chemical-weapons organisations, the export-control regimes, and the landmine and cluster-munition conventions. |
| International science and research facilities | 15 | Major shared laboratories and observatories — the European particle-physics laboratory, the fusion reactor project, the European molecular-biology laboratory, the southern observatory, the climate change panel, the renewable-energy agency. |
| Environment and climate funds | 7 | The global environment facility, the green climate fund, the adaptation fund, and the wetlands, endangered-species and conservation bodies. |
| Red Cross and Red Crescent | 2 | The two movement bodies that hold protected status under the Geneva Conventions. |
| Migration, humanitarian and cultural heritage | 4 | Migration policy, cultural-property conservation, demining, and armed-forces governance. |
| River-basin and navigation commissions | 5 | The Mekong, Nile, Danube and Rhine commissions and their sister bodies. |
| Sport governance (intergovernmental) | 2 | The world anti-doping agency and the court of arbitration for sport. |
| Standards, metrology and other intergovernmental bodies | 15 | The economic co-operation organisation, the G20, the permanent court of arbitration, the customs organisation, and the international weights, measures, standards and electrotechnical bodies. |

Subdomains of anything on the list are refused too, so a departmental address
under a protected body is refused along with the body itself.

The module is written to be genuinely hard to fool. It folds several Unicode
characters that browsers treat as a dot but ordinary text processing does not, so
a lookalike spelling of a protected domain cannot slip past. It extracts the host
under **two different interpretations** — because two widely-used web client
libraries genuinely disagree about how to read a backslash inside a web address,
and a block list that matches only one interpretation is bypassable by whoever
uses the other. It blocks if *either* reading reaches a protected host.

The module cannot be switched off, takes no configuration, consults no AI, and
can only ever say no. It never authorises anything.

#### The `.gov` / `.mil` question, answered

This is the first operational question a national agency will ask, so it is
answered here in full rather than left as a caution. Three facts, in order.

**Fact one: the block, as written, would refuse an agency's own estate.** The
module makes no distinction between an agency attacking someone else's government
domain and an agency assessing its own. A `.gov` or `.mil` host is refused on
sight, by name, before the charter is read.

**Fact two: today that block is not actually load-bearing.** I traced every
reference to this module in the whole repository. Outside the module itself and
its own test file, the only references are two lines in its package's index file
that make it importable. **No code on the live engagement path calls it.** So at
the version examined, pointing the system at a `.gov` host in a signed charter
would *not* be stopped by this control — it would be governed by the charter scope
check, the authorisation gate, and the network floor described above, exactly as
any other host would be. Two things follow, and they are uncomfortable in opposite
directions: the categorical protection is weaker in practice than the module's
existence suggests, and the obstacle for an agency is, today, theoretical.

**Fact three: there is no supported way to grant an exception.** The module takes
no configuration. There is no setting, no environment variable, no charter field,
and no signed-exemption mechanism that would let an owner authorise their own
`.gov` estate while leaving everyone else's protected. If the module were wired
onto the live path as its own documentation intends, the only ways to test a
government estate would be to edit the source — deleting or narrowing the suffix
patterns and the named list — and rebuild. That is a code change: it is visible in
version control and in review, but it is a blunt instrument, because narrowing the
rule for your own estate narrows it for every other government estate at the same
time.

**What is lost if the rule is narrowed, and what replaces it.** The rule exists as
defence in depth: it is the one control that a prompt-injection attack, a typo, or
a confused AI cannot argue with, because it runs before any reasoning happens.
Remove it and the remaining controls are the signed charter scope, the six-check
authorisation gate, the always-denied network floor, and the firewall — all real,
all described above, but all of them further down the chain and none of them
categorical.

**The honest status.** The right product change is neither "delete the rule" nor
"leave it and hope": it is a narrow, owner-signed exemption that admits only the
specific government hosts named in a signed charter and continues to refuse every
other protected domain. **No such mechanism exists in the code today.** An agency
evaluating this system should treat the `.gov` question as open product work, ask
for it explicitly in procurement, and not accept a verbal assurance that it "just
works". Any change here should also re-wire the module onto the live path at the
same time, so that the categorical block becomes real for everyone else at the
moment it is relaxed for the customer.

**One further limit of the block.** It matches by **domain name** only. A bare
numeric internet address is not caught by it — the code says so explicitly and
points to the charter scope and the network block list as the controls that cover
those. So even a fully wired categorical block would not stop a government system
being reached by its number rather than its name.

### 2.6 The whole gate chain, in order

Section 2.1 described one gate. It is not the only one, and the honest picture is
that there is no single gate at all. There are four distinct chains for four
distinct kinds of action, plus the network boundary underneath all of them and a
separate check on the system's own model calls. Anyone who merges them into one
will end up with a picture an engineer can falsify, so they are set out here
together.

**A request the engine sends to a target — five gates, in this order.**

| # | Gate | Refuses when |
|---:|---|---|
| 1 | Authority and emergency stop | The engagement is halted, expired, out of scope, destructive without permission, or out of budget — the six checks of section 2.1, run before any traffic so that a stop takes effect at the very next action. |
| 2 | Scope | The target is not in the signed charter. The refusal is counted as well as recorded. |
| 3 | Destructive confirmation | The request is classified destructive and the operator declines — **or does not answer in time**. |
| 4 | Budget | The engagement's request budget is exhausted. |
| 5 | Rate limit | It never refuses. It waits, for as long as the posture in section 7.1 requires. |

Three details inside gate 1 are worth having. The emergency stop is re-read from
disk on **every** action and works on its own, without a full authorisation
document behind it. The other five checks of section 2.1 run only when a signed
authorisation is actually loaded. And that is not a way to slip past them: if a
signed authorisation was *expected* — because automatic loading was requested and
a trust anchor was pinned — but none could be loaded or verified, the action is
refused outright, on the stated reasoning that the whole chain of time bounds,
action limits and destructive constraints must never silently switch itself off.

The order is described in the code as load-bearing, and both of the engine's
request paths call the same function to run it. The reason is stated plainly: a
new confirmation mode must not be able to become a hole in the safety stack by
acquiring its own copy of the sequence.

The same chain is re-run on every **redirect**. A web server can answer a request
by saying "go and ask this other address instead", and without a second check an
in-scope address could bounce the tool onto an out-of-scope one — an internal
service, a third party, or the cloud metadata address of section 2.3. The code
names that gap and closes it: every hop is gated exactly as the first request was.

**A registered tool or sensor — five gates.**

| # | Gate | Note |
|---:|---|---|
| 1 | Emergency stop | Checked first, as everywhere. |
| 2 | Licence | Against the capability the tool itself declares — the entitlement system of section 3.2. |
| 3 | Charter scope | Only when the tool names a concrete host. It reads two conventional field names, so a *sensor* that gathers from a host is scope-checked exactly as an attacking tool is. |
| 4 | Destructive confirmation | |
| 5 | Outbound address list | Only when the tool declares which hosts it will reach. |

Two properties here are worth stating on their own. Every gate is fail-closed: a
refusal, **or an error inside a gate**, refuses the invocation and the tool never
runs. And the intention is written to the permanent record **before** the gates
run, so a call that was refused appears on the record alongside the ones that
succeeded.

**The composed decision that both halves of the system share — three conditions,
all of which must hold.** This is the piece of code the project calls its gate of
record. It lives in the neutral shared core, so the sovereign half and the
offensive half use the same one rather than two that could drift.

| # | Condition | Refuses when |
|---:|---|---|
| 1 | The engagement authority | Anything in the six checks of section 2.1 says no. It is checked first because its emergency-stop step is the absolute stop. |
| 2 | The danger tier | The classifier's outcome is anything other than an explicit `auto`. |
| 3 | The multi-party quorum, for destructive actions only | There is no quorum, or no destruction gate was wired at all, or the gate errored. |

Four refusal behaviours in that composition are pinned by tests, and each closes a
specific way a safety check quietly stops working:

- A condition that throws an error is a refusal, never a caught-and-continued
  pass.
- The destructive condition is checked for the value *exactly* true, not merely
  for something true-ish. A buggy or hostile gate returning the text "no", or the
  number 1, cannot open an irreversible action.
- An *unrecognised* tier outcome is a refusal. Only the literal word `auto` opens
  the gate, so a future outcome added by a later change can never silently allow.
- A destructive action with no destruction gate wired at all is a refusal, not a
  fall-through.

**A cloud or container-cluster capture — two gates, before any network traffic at
all.** These are the six confirmations described in section 1.4.

| # | Gate | Effect of a refusal |
|---:|---|---|
| 1 | The danger-tier authorisation, plus the emergency stop | Returns a **refused** result and **no capture**. |
| 2 | The cloud scope check of section 1.4 | The same. |

The design note is the point, and it is short: a refusal produces nothing to
adjudicate, so there is nothing to launder. No network call is even constructed,
let alone sent, until both gates have passed.

**Underneath all four chains** sits the network boundary of sections 2.3 and 2.4 —
the permanently denied address ranges that no charter can unlock, the host
firewall that drops packets without reading words, and the filtering proxy outside
the sandbox's control.

**Alongside all four** sits one further check that is not about the target at all:
the sovereignty gate on the system's own model calls, described in section 3.3. It
governs where the system's reasoning happens rather than what it may attack, and
it refuses before a model client is constructed.

---

## 3. Permission tiers: sorting actions by how much damage they could do

Every action the AI wants to take is classified into one of four danger levels
before anything else happens. The classifier is a small, fast, AI-free program. It
reads the *name* of the action and nothing else — not the target, not the
arguments, and none of the text the AI wrote to justify it.

| Tier | What it covers | What it permits | What it requires |
|---|---|---|---|
| **A0** | Observing and answering only, and only for a fixed list of known-safe words: read, search, query, get, list, status, view, inspect, and similar. | Runs immediately, without being queued. | Nothing beyond the name matching the safe list. |
| **A1** | Reversible internal changes: draft, note, report, commit, branch, tag. | Runs immediately, and is recorded. | Nothing beyond the classification — but on the offensive side the minimum tier described in 3.1 lifts every tool above this, so nothing offensive ever runs at A1. |
| **A2** | Anything visible outside the system: send, email, publish, post, upload, export, download, sync, and bulk movement of data. | Does not run until a human approves. | An approval — by default a signed, single-use permission slip for that one action (section 4.2). |
| **A3** | Destructive actions, financial operations, key and restore operations — **and any action touching dangerous material at all**: secrets, credentials, tokens, keys, identity and access policies, firewall rules, roles, grants, and anything named production, root, admin, or vault. | Never runs automatically, under any setting. | The same explicit, per-action authorisation, and — where the action is irreversible — the multi-party quorum of section 5. |

The program has three names for those outcomes rather than four: `auto` covers
both A0 and A1, `queued` is A2, and `explicit-required` is A3.

### The complete vocabulary

The classifier is a dictionary, and the whole dictionary is short enough to print.
None of the lists below is a sample. These are all the words there are, and a name
matching none of them is treated as maximally dangerous. The counts were taken
from the source.

**A3 — seventy-five words.** Any one of them, anywhere in the name, makes the
action A3. They fall into five groups.

| Group | How many | The words |
|---|---:|---|
| Destructive verbs | 28 | push, deploy, delete, destroy, drop, remove, purge, wipe, truncate, overwrite, erase, format, kill, shutdown, reboot, reset, disable, enable, override, force, sudo, exec, eval, chmod, chown, patch, install, uninstall |
| Cryptography and reversal | 6 | encrypt, decrypt, restore, revert, rollback, recover |
| Money | 12 | spend, purchase, pay, payment, transaction, transfer, refund, invoice, allocate, budget, release, sign |
| Dangerous material, whatever the verb | 24 | secret, secrets, credential, credentials, token, tokens, key, keys, iam, policy, firewall, acl, role, grant, revoke, rotate, escalate, infra, prod, production, env, master, root, admin |
| Secret stores | 5 | vault, keyring, keychain, keystore, hsm |

Note what the fourth and fifth groups do. Most of those words are *nouns* — the
material itself rather than an action on it — and they make an action A3 no matter
what is being done to them. "Read the secrets" is not a read. "Get the budget" is
not a get. "Read the vault" is not a read. The code's own test file pins exactly
those three cases, along with `credentials.get` and `keyring.get`.

**A2 — twenty words.** send, email, smtp, publish, post, message, outbound,
webhook, sms, notify, share, upload, invite, calendar, tweet, dm, export, dump,
download, sync.

Two of them deserve a note. `export` and `dump` sit here because bulk movement of
a private store out of the system has to be seen by a person, even though nothing
is destroyed by it.

**A1 — twelve words.** write, note, brief, report, draft, alert, consolidate,
commit, branch, annotate, tag, label.

One word is deliberately *absent* and the code explains why: `snapshot`. Taking a
snapshot sounds harmless, but restoring one silently reverts the system's state.
So `restore` is A3, and a bare snapshot-create is left to fall through to A3
rather than risk it running by itself.

**A0 — seventeen safe verbs, plus eight exact names.** The verbs: read, search,
query, get, list, status, recall, observe, answer, view, show, find, frame, peek,
describe, inspect, lookup.

They are verbs only, never nouns, and the code states the reason: a safe *noun* on
this list would let "encrypt the memory store" reach the automatic tier because
the target happened to be a harmless one.

The eight exact names are read-only memory tools written out literally rather than
recognised by verb: `memory.search`, `graph.query`, `ingest.status`,
`graph.entity`, `episodic.range`, `threads.open`, `commitments.due`,
`contradictions.pending`. The first three would reach A0 on their verb anyway. The
other five contain no safe verb at all, and without the literal listing they would
fall to A3 — which shows the direction the design errs in even for its own
housekeeping tools.

**Seven exact names for gesture control.** Where the system is permitted to drive
a mouse and keyboard on the operator's own machine, there is no honest verb for
"inject input", so seven names are listed literally: four pointer actions — move,
click, scroll and drag — at A1, and three at A2, namely typing, key combinations,
and launching an application. These are checked *after* the danger pass, so
`hid.pointer.delete` is already A3 before the list is consulted. And the ordinary
words `move`, `type` and `click` are deliberately kept out of the dictionary
altogether, so `file.move` and `data.type` still fall to A3.

### The order the classifier works in

The order is the design, so it is worth setting out step by step.

1. Split the name into whole words — on full stops, underscores, hyphens,
   slashes, spaces, and on four invisible control characters — then lowercase it.
2. No words at all? A3.
3. Any A3 word? A3. This is checked before everything else.
4. Any A2 word? A2.
5. Any A1 word? A1.
6. An exact gesture name? A1 or A2, as listed above.
7. An exact safe tool name, or any A0 verb? A0.
8. Anything else whatsoever? A3.

Four design decisions inside that sequence deserve attention:

- **Danger is checked first.** An action touching a credential is A3 no matter how
  innocent the verb is. "Read the vault" is not a read; it is A3.
- **Anything unknown falls to A3.** The classifier uses a *positive* list of safe
  words. It does not try to list dangerous words and let everything else through.
  An unrecognised action, an empty one, or one it cannot parse is treated as
  maximally dangerous. This is the single most important property in the section:
  the absence of danger is not sufficient for automatic execution. A name has to
  be positively recognised as safe, or it is treated as maximally dangerous.
- **Matching is by whole word, never by fragment.** The action name is split on
  punctuation and spaces before matching, so `overwrite` is not mistaken for
  `write` and `forget` is not mistaken for `get`.
- **Hidden control characters cannot smuggle anything past.** The splitting also
  breaks on the invisible separator characters, so an action name with a dangerous
  word hidden behind one of them still classifies as A3. Both copies of the
  classifier carry the same short argument for why extra splitting is always safe:
  every word in the dictionary is itself free of separators, so splitting more
  aggressively can only ever *expose* a dangerous word, never break one in half
  and hide it.

### What a refusal looks like

The gate that consumes the tier returns one of exactly three outcomes, and the
difference between them matters to an operator reading a log.

| Outcome | When | What happens |
|---|---|---|
| `auto` | The tier is at or below both the automatic bar (A1) and the ceiling in force | The call runs. |
| `queue` | The tier is A2 or above, or above the ceiling | The call stops and waits for a person. A valid, single-use, owner-signed slip for this exact call lets it run once. With no signing authority provisioned, or no slip inside the time window, it is blocked. |
| `deny` | An empty name, or a name on a hard block list | An error is raised at once. It never runs, and it never even queues. |

Every branch fails toward refusal. A classifier that returns something the gate
does not recognise is treated as A3. A floor value the gate does not recognise is
treated as A3. The optional version of the classifier that runs the sovereign
kernel as a separate program treats a missing program, a timeout, a non-zero exit
and unreadable output all as A3 — and it refuses to run a bare `sigil-kernel`
name found on the system's search path at all, on the stated reasoning that an
attacker who placed a program of that name there would then be the one deciding
the tiers. An approval step that throws an error is a block, not a pass.

### The one file that can change a tier, and the direction it can move it

The sovereign kernel reads a plain-text file of per-tool overrides
(`~/.sigil/warden/tools.json`), so an owner can mark a particular tool as more
sensitive than its name suggests. That file is unsigned, and anything able to
write files on the machine could edit it.

It is safe anyway, because the override is **raise-only**: the effective tier is
the *higher* of the pin and the inferred tier. An attacker who pins the
code-push tool down to the automatic tier still gets A3, and the code's own test
asserts exactly that. Two keys differing only in capitalisation resolve to the
higher of the two rather than to whichever the program happened to read last. A
malformed or missing file is ignored, and inference governs alone.

The code records the matching limit honestly rather than hiding it: because the
file is unsigned, *lowering* a tier is not available through it at all. Legitimate
de-escalation would need a signed mechanism, and none exists.

There is a second version of this classifier written in a different programming
language, used by the personal/sovereign half of the system. The two are kept
identical by testing both against a shared set of reference cases, so they cannot
silently drift apart and start disagreeing about what is dangerous.

Deciding is only half of what the sovereign kernel does. After the caller has run
or blocked the tool, the kernel appends a signed, chained record of what happened
— the agent, the tool, a fingerprint of the arguments, the tier, the decision, the
approver, a fingerprint of the result, and the time. Its own header states the
boundary: it "never executes tools itself; it decides and it records". Section 9
covers what that record is worth.

### 3.1 The rule that makes offensive tools safe

On the offensive side, two additional rules apply on top of the tiers.

**A ceiling.** The automatic-approval ceiling for offensive work defaults to
**A1**. Since the floor described next lifts every offensive tool to A2 or above,
the two settings together mean that **an autonomous agent can never fire an
offensive tool by itself.** It always queues for a human.

**A floor that only ever raises.** A separate guard imposes a minimum tier
(default A2) on offensive tools, and it is written so that it can only ever move
a tool *up* the danger scale, never down. The reason is concrete: an offensive
action with a read-shaped name, such as `http.get`, `dns.query` or `port.list`,
contains a safe verb and would otherwise classify as A0 and run automatically.

So three separate mechanisms can move an action's tier, and all three are
one-directional. The override file raises. The floor raises. The ceiling caps what
may run without a person. Nothing in the system lowers a tier.

**Which classifier actually runs during an engagement.** The offensive side does
not call the sovereign kernel program for this. It uses a small function inside
its own process, and the honest description is this. The *dangerous* half is not
local: it imports the shared classifier and asks it the single question "does this
name carry one of the seventy-five dangerous words?", so a dangerous name can
never be rated differently on the two sides of the system. The *benign* half is
local and deliberately coarse — a curated list of eight danger-free
reconnaissance tool names (`nmap`, `httpx`, `nuclei`, `ffuf`, `curl`,
`subfinder`, `gau`, `katana`) rates A1, and every other name rates A2. Since the
floor and ceiling then decide the outcome, the only thing the local half changes
in practice is the label written into the record.

There is also a **tool-to-phase manifest**: each tool is listed against the phases
of work in which it may be used at all, and a tool not listed for the current
phase is denied. The port scanner and web probes are permitted during
information-gathering and exploitation; the database-injection and password
brute-force tools are permitted only during exploitation and post-exploitation.
An unlisted tool is denied by default.

### 3.2 Having the software is not the same as being allowed to use it

There is a second, quite different permission system underneath the danger tiers,
and it answers the question every government buyer of an offensive tool asks
first: **if a copy of this software is stolen, or leaks, or walks out on a
departing employee's laptop, what can the thief actually do with it?**

The answer the system is built to give is: *not much*. The most dangerous parts
of the engine do not run merely because the code is sitting on a disk. They run
only against a separate signed document the project calls an **entitlement**.

The everyday comparison is a controlled-substance licence rather than a padlock.
Owning the equipment is not the offence and is not the control; operating it
without the licence is what is refused. Copying the software copies the equipment.
It does not copy the licence.

**The ladder of capabilities.** Every dangerous power in the engine is named, and
each name sits on one of four rungs. There are eleven names in total, and the code
refuses to start at all if anyone ever adds a twelfth without placing it on a
rung — so a new dangerous power cannot quietly inherit the safest setting.

| Rung | The named powers on it | Plain meaning |
|---|---|---|
| **Baseline** — always available, no licence needed | Core reasoning; passive intake | Thinking, and building a picture of a target from material that is already public. Nothing is attacked. |
| **Standard** | Active reconnaissance; autonomous planning; defensive blocking | Actually touching a target to look at it; letting the system plan its own next steps; and, on the defensive side of the product, allowing it to block a proven attack on the operator's own application rather than only watching. |
| **Offensive** | Exploit execution; deep source-code analysis; defender telemetry | Running a single proof-of-impact against one weakness; the heavyweight white-box code analysis; and scoring how visible the system's own actions would be to a defence team. |
| **Advanced** — the most dangerous, licence-locked | Full-chain exploitation; defender evasion; self-improvement merge | Stringing several weaknesses into one working attack; defeating a named production defence; and letting the system merge changes into its own source code. |

An honest note about that last rung: **the three advanced powers are names on the
ladder, not working features.** No code in the engine asks for full-chain
exploitation or defender evasion — the modules that would use them are
deliberately absent, and the layer that comes closest to them carries an explicit
list forbidding it from ever requesting the three. They are on the ladder so that
if anyone ever builds them, they arrive already behind the highest gate rather
than slipping in below it. Self-improvement merge is the one of the three that a
real piece of code consults, and it only ever decides whether a *proposal* may be
merged (see section 10).

**What an entitlement is, in the ordinary sense of the word.** It is a small
signed file with five properties, each checked in a fixed order, and the first
failure wins:

1. **Signed by several people, not one.** It must carry signatures from a minimum
   number of a named set of authorising officials — the governance authoriser set
   — exactly as a licence might need two named signatories rather than one.
2. **Time-boxed.** It has a start and an end. Outside that window it is void.
3. **Tied to a specific machine.** It names the identifiers of the host it was
   issued for. Copy the file to another machine and it stops working there. The
   code's own words: a stolen entitlement file is useless off its attested
   machine.
4. **Revocable.** A separate signed revocation list can name an entitlement as
   cancelled, and a cancelled entitlement is refused even though its signatures
   are still perfectly valid.
5. **Least privilege inside the rung.** A licence for a rung may additionally list
   only the specific powers it grants. Listing a power *above* the rung does not
   raise it; it is simply ignored.

An entitlement may optionally also be tied to a named operator identity, and a
process that presents no identity at all when the licence demands one fails
closed.

**The safe core never depends on the licence.** The baseline rung runs whatever
happens — even with no licence, and even when a licence is present but broken. The
design point is that a tampered or expired document degrades the system to a safe
observer rather than bricking it or, worse, failing open.

**Issuing is deliberately not a convenience feature.** The running system only
ever *verifies* entitlements. Creating them — building the trusted set of
authorisers, signing a licence, issuing a revocation — is a separate governance
ceremony performed elsewhere, on a machine where the authorising officials' private
keys live. The code says plainly that those keys are the institution's crown
jewels, that they never belong on a machine that runs the tool, and that they never
belong in source control. The command-line verb an operator has is read-only: show
the current state, list every power and whether it is available, and re-check the
provisioned files.

**The honest caveat, and it is a large one.** Enforcement switches on only when a
deployment has been given a trusted set of authorisers (or has had enforcement
turned on explicitly). Until then the deployment is what the code calls
**ungoverned**: the baseline still runs, and the gated powers are *permitted* —
each grant written to the log with a warning, and the status command saying in as
many words that the deployment is ungoverned. This default exists so that a
developer's working copy runs without a licensing ceremony. The consequence for a
buyer is direct and must not be glossed: **on a freshly installed system this
protection is not in force.** Provisioning the trusted authoriser set is the single
step that makes it real, and an agency should treat that step as part of accepting
the system, not as optional tuning.

**Where the gate actually bites.** This is not a decorative layer. The licence
check is called at the entry point of the exploitation agent, the gated
proof-re-execution layer, the general tool invoker that every agent tool call goes
through, the deep source-code analysis pipeline, both live reachability probes, the
self-visibility scoring component, the runner that drives external security tools,
the request-replay tool, and the defensive gateway's active-blocking mode. Where
the licence is absent in a governed deployment, the defensive side says so on the
screen — it reports itself as downgraded rather than pretending to block.

### 3.3 A third ladder: where the system's own thinking is allowed to happen

The two ladders above govern what the system may do. A third governs something an
agency will care about at least as much: **where the system's own reasoning
physically takes place, and therefore where the customer's data goes.**

The reasoning inside this system is done by a large language model. Some models
run on the operator's own machine. Others run on somebody else's computers,
reached over the internet, which means that whatever is put in front of them —
including details of the customer's systems and their weaknesses — leaves the
building. That is a sovereignty question rather than an authorisation one, and it
has its own separate ladder with its own separate refusal.

The operator picks one of four tiers by setting a single environment value.

| Tier | What it permits | What it refuses |
|---|---|---|
| **AIR_GAPPED** | Local models only. | Every cloud model, refused **at construction** — before a client object is built, before the vendor's software library is even loaded, and therefore before anything could be sent. |
| **SOVEREIGN_CLOUD** | Local models, plus cloud models running on jurisdictionally bounded infrastructure where the operator chooses the region. | The direct consumer model interfaces. |
| **TRUSTED_CLOUD** | The above, plus a frontier model offering under a zero-data-retention contract. | The direct consumer model interfaces, still. |
| **PERMISSIVE** | Everything. | Nothing. This is the development default. |

The ladder exists in four rungs rather than as an on/off switch for a reason the
code states: most government workloads need *jurisdictional* sovereignty — data
residency, regional infrastructure, contractual handling — rather than pure local
operation, and forcing that choice to be binary would push it underground.

**Every model the system knows about is placed on the ladder by name.** There are
thirteen, and this list is exhaustive:

| Class | The models in it | Permitted from |
|---|---|---|
| Local — runs on the operator's own machine, no network egress | Ollama, vLLM, llama.cpp, TGI, a generic self-hosted endpoint, and a dry-run stub with no network at all | AIR_GAPPED upward |
| Jurisdictionally bounded cloud | Amazon Bedrock, Google Vertex AI, Mistral's platform | SOVEREIGN_CLOUD upward |
| Contractually bounded cloud | The zero-data-retention Anthropic offering | TRUSTED_CLOUD upward |
| Ordinary cloud, with no special data-handling agreement | The direct Anthropic interface, the Claude Code interface, and a bring-your-own Azure OpenAI resource | PERMISSIVE only |

**It fails closed in four separate places**, and this is a good worked example of
the house style:

- **An unrecognised tier name resolves to AIR_GAPPED**, the strictest one — not to
  the most permissive, and not to an error. A typo in the setting tightens the
  system rather than loosening it.
- **An unrecognised model name is classified as ordinary cloud**, so it is refused
  under every sovereign tier. A model the policy has never heard of does not get
  the benefit of the doubt.
- **If the policy code itself cannot be loaded** by the process making the call,
  and any sovereign tier is configured, the call is refused — the stated reasoning
  being that the process cannot prove the egress is permitted, so it must not
  perform it. If no tier is configured at all, the policy would have resolved to
  PERMISSIVE anyway, so behaviour is unchanged. The code names the property
  directly: this can over-refuse, and it can never under-refuse.
- **If the gate itself throws an error**, that is a refusal, never a permission.

One further detail is the difference between a control and a gesture. The refusal
is delivered by *returning the safest available action* rather than by crashing,
so that the reasoning loop stays intact and the operator gets an explanation. The
enforcement is still real, and the source says so in one sentence: the client is
never constructed, the vendor's software library is never imported, and nothing
leaves the host.

**The zero-data-retention step is an attestation, not a proof.** Moving a direct
model interface out of the ordinary-cloud class and into the contractually bounded
one is done by the operator setting a flag that says "this key is covered by a
zero-data-retention agreement". The code labels it an attestation in as many
words. The system cannot check the contract. It records the operator's claim and
behaves accordingly.

**There is an optional seal.** By default the tier is re-read from the environment
on each call, which is convenient while developing but means a change made
part-way through a long-running process takes effect immediately. Setting a
further value latches the tier once for the lifetime of the process, so a later
change cannot relax it mid-engagement. The seal can only ever pin the tier; it can
never loosen it.

**Where the check is made.** Four places in the system construct a model client,
and all four consult the same policy first: the reasoning step behind a live
engagement, the automated code-fix component, the console's chat-style terminal,
and the engine's own model-backend factory. That last one places the check before
the import, so under a strict tier the system never even loads the cloud vendors'
software in order to probe whether it is available.

**The honest limit, and it is the same shape as the licensing one in 3.2.** With
nothing configured, the default tier is **PERMISSIVE**, which the code itself
describes as equivalent to no policy enforcement. A freshly installed system does
not restrict where its reasoning happens. Choosing a tier is a deployment act, and
an agency should treat it as part of accepting the system rather than as optional
tuning. Item 16 of section 14 records this.

---

## 4. The approval queue: where a human says yes

When an action is queued, a person has to approve it. The system offers two ways
to do that, and it is honest about the difference in assurance.

### 4.1 Standing approval — the lower-assurance mode

The operator can start a run with a single flag that blanket-approves every
queued action for that run. This exists, it is real, and the system labels it in
its own documentation as the **explicit lower-assurance standing mode**. It is
not the default.

### 4.2 Per-action signed approval — the default

The default for offensive tools is a cryptographically signed permission slip for
**one specific action**. It has four properties, each of which closes a specific
attack:

1. **It is bound to the action.** The slip names the exact tool, the exact
   target, and a fingerprint of the exact action. It cannot be re-used to
   authorise something else.
2. **It is checked against a fixed owner key.** The public key it is verified
   against is fixed when the system is set up — not supplied with the request.
   The code explains why: if the request could name which key to check against, a
   compromised worker process could simply name its own key.
3. **It expires quickly.** The slip is valid only inside a bounded window, and the
   policy caps the maximum lifetime at fifteen minutes. The purpose, in the code's
   own words, is to stop the owner from pre-signing a long-lived "sleeper"
   permission that could be woken up later.
4. **It can be spent exactly once.** Spending is recorded by creating a marker
   file in a way the operating system guarantees only one process can win. If ten
   processes present the same slip at the same moment, exactly one succeeds. The
   spend happens **only after** the signature, the binding, and the time window
   have all passed — so an invalid slip cannot be used to "burn" someone else's
   valid one out of spite.

### 4.3 How the request and the signature travel — and why the key never moves

The system is split into two halves that run as separate programs. The
**sovereign** half holds the owner's signing key. The **offensive** half holds no
owner key at all.

So the approval flow works like this. The offensive worker publishes a
**redacted, public-safe** description of the action it wants to take. The owner —
on the sovereign side, the only place the private key exists — reviews it and
writes back a signed slip. The offensive worker spends the slip.

Two consequences follow. First, the offensive side can never sign its own
permission, because it has nothing to sign with. Second, the description that
travels is scrubbed of secrets before it is published.

There is one further rule that is easy to miss and important: **a signed approval
never widens scope.** It satisfies the *human* condition for an action that the
authorisation gate has already placed inside the envelope (that is, an action
that came out as "queue"). An action the gate **denied** stays denied. No amount
of signing turns an out-of-scope target into an in-scope one.

### 4.4 The control panel can show approvals but can never grant them

The browser control panel has a screen listing pending approvals. For the
offensive queue, that screen is **read-only by construction**: the console
process holds no key, and the endpoint that serves the list only supports
reading. What the screen offers is a copy-to-clipboard command that the operator
runs on the trusted machine. The screen says so on its face.

The sovereign half's approval screen *is* actionable — approve, deny, engage or
release the emergency stop, grant or revoke agent promotions — but the signing
happens on the server with the owner's key. The browser never holds a key.

That screen also enforces its own limits and says so on screen: a promotion
covering "everything" is not reduced by revoking one category, and two specific
agents (the one that drafts external communications and the one that acts on the
web) can **never** be promoted at all. This is enforced on the server, which
returns an explicit error, so a refused grant cannot be misread as a success.

### 4.5 The bundled agent's shell is gated by default

The system bundles a third-party agentic penetration-testing tool. That tool has
a general-purpose command shell — the single most dangerous surface in the whole
system, because it can run anything.

That shell is routed through the approval queue, and the gate is **on by
default**: no opt-in is required, and a queued shell command runs only once the
owner has signed a single-use permission slip for that exact command. Every other
tool inside that agent's sandbox runs automatically; the shell is the chokepoint.

**Exactly two names are gated, and the choice is deliberate.** The gate does not
use the general danger classifier of section 3 here. It uses a two-line rule: the
two names that start a command and feed a running one — `exec_command` and
`write_stdin` — are treated as the most dangerous tier, and every other name the
agent can call is treated as the safest. The reason is stated in the code and is
worth understanding, because it is a design choice rather than an omission. Every
command-line invocation the agent makes flows through `exec_command`, and
`write_stdin` types into a process an earlier `exec_command` already started. So
gating those two gates *all arbitrary execution*, while the agent's other tools
keep working and the agent remains functional. Applying the general offensive
classifier instead would rate almost every name as needing approval, which under
an always-on gate would stop the agent doing anything at all.

**What that leaves running automatically.** Naming those tools is more honest than
calling them "benign". Besides the shell, the vendored agent's tree holds twelve
other tool families. Eleven of them are things the agent calls by name, and every
one of those runs without an approval under this gate: private reasoning, notes, a
to-do list, web search, file patching, reporting, image viewing, skill loading, a
finish signal, spawning and co-ordinating sub-agents, and six tools over the
intercepting web proxy — listing captured requests, viewing one, replaying one,
listing the site map, viewing an entry in it, and reading the proxy's own scope
rules.

The twelfth is browser automation, and it is the interesting one, because it is
**not** an exception that slips past. It is not a named tool at all. It is a
command-line program installed in the sandbox, and the agent drives it through
`exec_command` — so every browser action the agent takes queues for approval like
any other command.

The replay tool is the one to look at hardest, since it re-sends a captured
request. It is an ordinary function call rather than a command, so this gate does
not see it. Something else bounds it: the gate deliberately judges a tool by its
**class and name, never by its target**, because deciding what a request may reach
is the job of the network boundary in sections 2.3 and 2.4. A replayed request
still has to get past the firewall and the filtering proxy, and those do not care
which tool sent it.

**The gate's own settings.** For this one surface the minimum tier is set to the
lowest value and the automatic ceiling to A1, which is what allows the agent's
other tools to run while the two shell names — rated at the top tier — land above
the ceiling and queue. The permission slip the owner signs is bound to the actual
arguments of the actual call, not to the static definition of the tool, so what
the owner sees and signs for is the real command. An earlier version bound a
constant here; that was found by the project's own adversarial review and fixed.

**How the gate behaves when it cannot be attached: it fails closed.** This was
until recently the one place in this briefing where a safety property was weaker
than a plain reading would suggest. It no longer is, and the change is worth
setting out, because the reasoning generalises.

The gate is not built into the third-party tool. It is *attached* to it at start-up
by a few lines of code that reach across from this project's own package into the
vendored tool. Those lines used to swallow any failure and carry on, on the stated
reasoning that a wiring fault should never stop a customer's scan. The effect was
that a broken wire produced an ungoverned shell with no signal to the operator — an
accident, and one indistinguishable from the outside from a healthy governed run.

That fallback has been removed. A failure to attach the gate now raises an error
that stops the run: the scan is recorded as failed, the agent's outstanding work is
cancelled, and the error text names both what broke and the environment setting an
operator would use to run without the gate on purpose. There are therefore exactly
**two** ways the gate can end up absent, and both of them are deliberate:

1. **The explicit opt-out.** An environment setting turns the gate off. This is a
   deliberate, visible act, reserved for running the vendored tool in an
   unmodified, ungoverned form.
2. **The tool is running on its own.** If someone runs the vendored tool from a
   bare checkout, without this project's package alongside it, there is nothing to
   attach and the tool behaves exactly as its authors shipped it. This is intended:
   the vendored copy is meant to stay byte-for-byte identical when it is not being
   governed. It is not a gap in a governed deployment either, because in a governed
   deployment the package is present — its absence is what *defines* the ungoverned
   case.

Any third outcome — a broken installation, a version mismatch, a bug introduced by a
future change — now stops the run instead of proceeding without the gate. The
narrowing is visible in the code at the point where the gate is attached: the only
failure still tolerated there is the specific one that means "this project's
package is not installed at all", which is case 2 above. Every other failure
travels up and stops the run.

So the claim can be made in its strong form: **turning the gate off is a deliberate
and visible act, and so is running without it; neither happens silently.** The gate
fails closed at attachment, and it fails closed in operation — a shell command with
no owner authority provisioned, or no valid single-use permission slip inside the
time window, is hard-blocked rather than allowed through.

There is a price, and a buyer should expect it rather than be surprised by it: a
fault in this wiring will now stop a scan instead of quietly degrading it. That is
the correct trade on the single most dangerous surface in the system, and a run that
fails this way should be read as the control working, not as a defect.

Two further notes for a reviewer:

- The strongest posture does not rest on this gate alone: run the vendored agent
  where its output is treated as a *lead* to be re-proved by the system's own
  checkers, and keep the emergency stop and the network firewall as controls that
  bound it independently of whether this gate attached.
- The property can be checked directly rather than taken on trust here. It is
  covered by a test that breaks the wiring deliberately and requires the error to be
  raised, paired with a companion test that repairs the wiring and requires the gate
  to be composed — so the first test cannot pass for the wrong reason.

---

## 5. Irreversible actions need several people

For the highest-consequence class of action, one human approval is not enough.
The system implements an **m-of-n** rule: a minimum number of independent
authorised signers, out of a registered set, must each sign the same action
before it can proceed.

Five properties are enforced, all failing closed:

1. **The threshold itself.** A specified number of distinct trusted signers must
   sign. The project is precise about what this delivers: it is genuine m-of-n
   *authorisation*. A more advanced cryptographic technique that compresses those
   signatures into a single small one is deliberately deferred, and the code notes
   that this is a size-and-verification refinement which does not change the
   security property.
2. **One mandatory signer, fixed in advance.** The set of signers who *must*
   participate is fixed when the system is deployed and cannot be named by the
   request. The reason is specific: the offensive worker is itself a registered
   signer, so if the request could nominate who counted as the owner, the worker
   could nominate itself. A quorum made only of workers and policies authorises
   nothing.
3. **Binding to the action.** The authorisation names the engagement, the target,
   the class of damage, and an action identifier.
4. **A dead-man's-switch.** The window is capped — the command-line tool caps the
   total at fifteen minutes — so a long-lived pre-signed authorisation is void.
5. **Single use.** Consumption is an atomic check-and-burn, using the same
   operating-system guarantee described above.

The system is candid about two limits here, both recorded in its own
documentation rather than discovered by an outside auditor:

- The action identifier is opaque to the gate. Binding it to the *real* command
  depends on the signer computing it from the command and the executor
  re-deriving it the same way. The gate never sees the command itself and cannot
  enforce that relationship. This is stated in the code.
- The command that mints a destruction authorisation writes its output file in a
  way that overwrites any previous file at that path, rather than refusing to
  overwrite. Single use is enforced downstream by the spend-ledger, not by that
  file write. This correction was found by the project's **own** adversarial
  honesty pass and written into the feature catalogue rather than quietly fixed
  in the prose.

### 5.1 The one destructive path that has been built — and its honest status

The only irreversible action wired up today is **opening a pull request** — that
is, proposing a code change to a source-code repository so a human can review and
merge it.

Even that is layered:

- The finding that justifies the fix must be **provenance-grounded**: either a
  signed sealed envelope verified against an owner-signed delegation, or a fact
  rebuilt from the signed record after an integrity audit. In the code's words, a
  plain data file is never accepted as a finding.
- Applying the fix happens in a **disposable copy** of the repository, which is
  then built in a sandbox. The operator's actual working files are never touched.
- Actually opening the pull request is **off by default** and requires all of: a
  signed authorisation, a trust anchor, at least one mandatory signer including
  the owner, the durable single-use ledger, and an access token in the
  environment.

**Status, stated honestly: built, not live-fired.** The path exists and is
tested, but exercising it for real requires the operator to provision the
multi-party signing keys and supply a repository access token. It has not been
run end-to-end against a live repository. It should not be described to anyone as
a proven field capability.

---

## 6. The emergency stop

There are two emergency stops, one on each half of the system, and both are
designed around the same asymmetry: **stopping must always be easy; restarting
must always be hard.**

### 6.1 The offensive-side stop

On the offensive side, the emergency stop is a file on disk, one per engagement.
Pulling the stop writes the file. While the file exists, the gate refuses every
action.

Three properties follow from that simple design:

- **It survives a crash or a restart.** There is no in-memory-only "halt" that a
  reboot could quietly undo. The code says this is the point: when an operator
  hits stop, it stays stopped until a human deliberately clears it.
- **It is checked first**, before scope, before the time window, before
  everything.
- **Ambiguity counts as stopped.** The code does not use the ordinary
  "does this file exist?" call, because that call quietly reports "no" for every
  kind of error — an unreadable parent directory, a broken link, a disk fault.
  For a hard stop, that is exactly backwards. Instead, only the specific error
  codes that *prove* the file is genuinely absent count as "clear"; permission
  denied, a link loop, or an input/output error all read as **stopped**.

Clearing it is a separate, explicit, logged act by a person. The system never
clears it on its own.

### 6.2 The sovereign-side stop

On the personal/sovereign side, the stop is a latch recorded on the append-only
record. It halts the agent mesh while leaving passive observation and
memory-reading alive.

Its authentication is deliberately **asymmetric**, and the code explains the
reasoning. Halting is the safe direction, so **any** halt signal halts — a forged
halt is at worst a nuisance that stops work. Un-halting is the dangerous
direction, so a release is honoured **only** if it is signed by the owner's key
and verifies against the trusted public key. A forged release can never revive a
halted system.

The verdict is re-read fresh for each decision, so a stop takes effect
immediately rather than at the next convenient moment.

### 6.3 It is visible where operators look

The status of the emergency stop appears as a live indicator on the control
panel's Activity screen and as a tile on the Approvals and Safety screen, with the
engage and release buttons and the on-screen note that halting is always safe and
immediate while releasing requires the owner's signed request.

---

## 7. Not damaging the systems under test

An assessment that takes down the service it was assessing has failed, regardless
of what it found. Several mechanisms address this.

### 7.1 Three operating postures, with different speeds

The charter selects one of three postures, and the posture changes the tool's
behaviour automatically:

| Posture | Minimum gap between requests | Identifying label on requests |
|---|---|---|
| **TEST** (the default) | 0.2 seconds | `OBSIDIAN/1.0 (authorized owner-test <date>)` — deliberately identifiable |
| **AUDIT** | 1 second | Same identifiable label |
| **EMULATE** | 5 seconds, plus a random extra delay of up to 3 seconds | A realistic browser label |

The identifiable label in the two normal postures is a deliberate choice recorded
in the project's operating doctrine: the operator should be able to search their
own logs and find exactly which traffic came from the tool. The tool is not
hiding from its own client.

The EMULATE posture — adversary emulation, used to test whether a defence team
can detect a realistic attack — is the only one that uses a browser-like label,
and the charter template requires an explicit written reason for selecting it,
together with additional limits, and states that even then it must cause no real
harm.

### 7.2 A hard request budget

Every executor carries a total request budget for its lifetime (defaulting to 100
in the live-HTTP executor). When it is exhausted, further requests are refused and
the refusal is counted. This is a backstop against a runaway loop.

### 7.3 Destructive-looking requests stop and ask, and a silence means no

Before issuing any request, the executor classifies it as destructive or not. It
treats two things as destructive.

First, any request that is *shaped* to change data on the server rather than
merely read it. A request to a website carries a verb. Some verbs mean "show me
this"; others mean "create, replace, change or remove this". The second kind is
always treated as destructive.

Second, any request whose web address contains one of twenty-three words that
usually signal a dangerous corner of an application. Website addresses are
readable, and the words in them tend to say what the page does. The twenty-three
fall into five everyday groups.

| Group | Why the system stops | The words it looks for |
|---|---|---|
| Administration | The address suggests an administrator area or an attempt to act as somebody else, hand out rights, or raise a privilege level. | `/admin`, `/sudo`, `/impersonate`, `/grant`, `/promote` |
| Destruction | The address suggests something is about to be removed or emptied. | `/delete`, `/destroy`, `/drop`, `/wipe` |
| Money | The address suggests real funds could move — a withdrawal, a transfer, a refund, a payout, or a checkout. | `/withdraw`, `/transfer`, `/refund`, `/payout`, `/payment/`, `/checkout` |
| Account recovery | The address suggests a password reset, which in a live system means a real email or text message to a real person. | `/reset`, `/password-reset`, `/forgot-password` |
| Bulk data and subscriptions | The address suggests files or records moving in bulk, a restore from backup, or a change to what a real user has signed up to receive. | `/upload`, `/import`, `/restore`, `/subscribe`, `/unsubscribe` |

The word only has to appear somewhere in the address for the request to be held.
That is deliberately blunt, and the reason is in the next paragraph.

The code's comment on this classifier is a good summary of the whole system's
temperament: erring toward refusal is correct, because a false alarm costs one
prompt to the operator, while a missed one could cost the engagement.

When a request is classified destructive, the operator is prompted — and the
prompt **defaults to no on timeout**. Silence is a refusal, not consent.

### 7.4 Charter-level manners

The charter's soft-limits section carries the operating manners: an off-peak
window for heavy scans; a default of five to ten requests in flight at once (the
tool can work on several requests in parallel to go faster, and this caps how
many), with anything higher needing per-action approval; the instruction to
respect the target's own rate limiting and back off — waiting longer after each
refusal — rather than fight it; advance notification before heavy scanners run;
and a single fixed source address so the traffic is easy to identify.

These are doctrine expressed in the authorisation document rather than numbers
compiled into the program. A reader should understand them as binding on the
operator and the AI's behaviour, and understand the posture rate limits and the
request budget in section 7.1 and 7.2 as the parts enforced in code.

### 7.5 Bounded sandboxes and bounded connections

The isolated command runner is time-boxed and its output is capped, so a runaway
command cannot fill the disk or hang forever. It is also configured so that
killing the parent kills the child — no orphaned processes are left running — and
so that it runs in a fresh terminal session, which closes an old trick for
injecting keystrokes back into the operator's own terminal.

The filtering proxy caps simultaneous connections and gives up on requests whose
headers arrive too slowly.

### 7.6 One honest nuance about "bypassing" defences

The offensive engine contains an opt-in capability to determine whether a web
application firewall can be bypassed. It works by trying an ordered ladder of
alternative encodings for a probe that was blocked, and — only if that ladder is
exhausted — a small, budgeted search for a novel encoding.

Its own documentation is clear about the boundary, and so should this briefing
be:

- It is **off by default** and must be opted into per engagement.
- Every request it makes goes through the same gated executor, and therefore
  through the same budget and the same rate limits. It is not an unbounded
  hammer.
- The result is still decided by the same deterministic checker as any other
  finding: a bypass that does not actually trigger the checker is not a finding.
- The code describes it as "a verification aid — prove a filter is bypassable —
  not an escalation weapon", and describes the search as "bounded and reported,
  never unbounded evasion".

This is a different thing from evading a *defence team*, which the project has
refused to build (section 10). It is worth stating both facts side by side so
neither is a surprise.

---

## 8. Staying away from real people's data

### 8.1 What the charter forbids

The hard limits in the charter template are the first line: no contact with real
users, no copying of real personal data beyond the minimum needed to demonstrate
impact (with a numeric cap and a requirement to redact it in the evidence), a cash
cap on any real money movement, and no bulk deletion. The stop conditions require
the system to halt and ask the moment it discovers it can read real personal
data, real payment data, or real credentials — and specifically instruct it not to
bulk-collect.

### 8.2 What the code does automatically

**Credentials are masked before they touch the disk.** Two places routinely
archive raw exchanges: the human-readable evidence files and the activity logs.
Before either is written, the *values* of credential-bearing fields are replaced
with a stable placeholder. The list is explicit and covers authorisation headers,
proxy authorisation, cookies in both directions, several styles of API-key header,
session and cross-site-request tokens, and cloud security tokens.

The scoping decision here is thoughtful and worth explaining, because it looks
like under-masking until you see the reason. The masking works by **field name**,
not by scanning free text for anything that "looks like a token". Over-masking a
response body would destroy the very evidence a finding rests on — the proof that
the vulnerability exists is often in the body. So the raw body is not masked; it
is protected instead by owner-only file permissions. In the code's own summary:
this masks the credential that authenticated the request, not the evidence it
produced.

**Passwords on command lines are masked in the permanent record.** The
password-guessing tool's inline password argument is explicitly masked in the
signed record of what was executed.

**Live credentials are reduced to a fingerprint and discarded.** The component
that tests whether a cloud server's metadata service leaks credentials handles
real secrets. Its design is strict: the plaintext credential is validated and
fingerprinted **in memory**, then discarded. Only a redacted structural record,
the fingerprint, and non-secret context are retained. The fingerprint is
domain-separated — mixed with a fixed label before hashing — specifically so it is
not a bare hash of the secret that could be checked against a guess list offline.
No live secret ever enters the evidence or the certificate.

**Everything on disk is owner-only.** The program latches a restrictive
file-creation setting at start-up, so every file it and its children create is
readable only by the operator's own account, with explicit owner-only permissions
on sensitive files and directories on top of that.

**There is a leave-no-trace mode.** The offensive engine supports an `--ephemeral`
run. Normally the engine writes its working files to the machine's hard disk,
where they survive a restart. In this mode every path it would write to is
redirected into a scratch area that exists only in the computer's memory — a
notepad rather than a filing cabinet — and that area is thrown away when the
session ends. Nothing is left on the disk. Reads are deliberately *not*
redirected: an ephemeral run still reads its real charter from the disk and stays
in scope. So the mode reduces what is left behind without reducing what is
enforced.

**Exported packages are scrubbed.** The single-file evidence package the system
produces for a client includes the engagement log in a **secret-scrubbed** form.

**Secrets are never returned to the browser.** The control panel can seal a key
into the machine's protected storage but can never read one back out. The screen
shows only whether a key is set, a fingerprint, and — where a live health check
exists — whether the key currently works. A broken or expired key shows as
**failing**, not as a reassuring green tick.

### 8.3 Test artefacts are tagged so they can be found and removed

The charter template requires every test account and every artefact created during
the engagement to carry a common prefix, so the operator can search their own
database for that prefix and identify everything the test created. This is
doctrine in the authorisation document; I did not find it enforced by a program.

---

## 9. The audit trail: everything is written down, and the record resists editing

### 9.1 What is recorded

- **Who used the tool, when, and against what** — the usage attestation described
  in section 1.5, minted before every run.
- **Every event in an engagement** — observations, hypotheses, plans, actions,
  results, findings — on an append-only record the project calls the *spine*.
- **Every refusal** — this is important and easy to overlook. When a gate says no,
  that refusal is written into the record as evidence. The system's own operating
  doctrine states the principle: refusals are evidence; record them, never hide
  them. An operator reviewing a run can see not only what the tool did but what it
  wanted to do and was stopped from doing.
- **Every governed command run** — the local read-only terminal and the isolated
  sandbox both produce a signed, redacted record of what was executed.
- **Every confirmed finding** — as a signed certificate over the exact evidence.

### 9.2 Why the record is hard to edit

Append-only is enforced at three independent levels:

1. **The database refuses.** Rules inside the storage engine reject any attempt to
   update or delete an event row directly.
2. **The programming interface offers no way.** There is no update function and no
   delete function. Corrections are made by *adding* a new record that points at
   the one it supersedes. Normal reads hide superseded records; a history view
   shows them. The new record inherits the old one's parentage, so the chain of
   reasoning survives the correction.
3. **A cryptographic chain sits on top.** Each entry is bound to the one before it
   by a hash, and the whole chain is signed. That means tampering which
   *bypasses* the database entirely — editing the file directly, or swapping it —
   is still detectable.

Two further details: the chain deliberately does **not** include the wall-clock
timestamp in what it protects, so that replaying a run produces an identical,
comparable chain; and the engagement's identity **is** bound in, so a signed chain
head cannot be lifted onto a look-alike log. If the log cannot be read to
completion, the code raises an error rather than signing a truncated log.

### 9.3 What an inspector can run

- `vigil ledger who` and `vigil ledger when` replay the usage record.
- `vigil verify-ledger` re-checks that the chain is intact.
- `vigil verify` re-checks a run's findings.
- `vigil dossier` compiles an entire run into one self-contained, tamper-evident
  archive with a manifest of digests.
- `vigil proof-export` produces a package a third party can verify **offline**,
  with no part of this system installed.

The control panel's Governance screen presents the same information read-only: the
conditions every action must clear, the multi-signature threshold and its
registered signers, the count of already-spent single-use authorisations, and any
pending ones. The screen states on its face that it cannot provision, authorise,
or fire anything.

### 9.4 The honest limits of the audit trail

The project documents these itself, and they should be repeated here rather than
buried.

- **Consistency is not completeness.** Re-checking the chain proves that the
  records presented are internally consistent, in order, and unforged. It cannot,
  by itself, detect that the *most recent* records were dropped or the whole file
  wiped — because a valid beginning of a chain is still a valid chain. To catch
  that, the checker must be given an externally kept anchor (the expected head and
  count). The code supports exactly that.
- **The rollback floor is local.** The file that stops the record being rewound is
  an ordinary owner-only file. The documentation states the limit plainly: an
  attacker who already has the owner's account (or administrator rights) on the
  same machine can rewrite the log and the floor together. What the floor
  guarantees unconditionally is that it only moves forward, refuses a downgrade,
  and advances safely across a crash. Defence against a fully dishonest producer
  requires the external witness described below, not this file.
- **Witnesses prove continuity, not truth.** The system can have independent
  witnesses countersign that a new checkpoint properly extends the previous one.
  The trust document is explicit that a witness does **not** attest that any
  finding is true, that a fix holds, or that a checker fired — only log continuity
  and a time bound. It says conflating "witnessed" with "true" would be an
  overclaim.
- **Resistance to showing two different histories to two parties is
  conditional.** It holds only when a strict majority of distinct witnesses
  countersign. Below that — in particular with a single witness, which the trust
  model permits — two conflicting versions can each be properly countersigned
  without any witness behaving dishonestly; what remains is detection, not
  prevention. The system has a separate check that proves whether a given witness
  set actually meets the strict-majority bar.
- **Distinct keys are not distinct operators.** The witness trust document, which
  is marked "draft — design, not a guarantee", states the assumption code cannot
  enforce: if the party producing the records holds all the witness keys, the
  quorum is theatre. Genuine independence of witnesses is a **deployment**
  decision, not something the software can prove. The project records this as one
  of its remaining honestly-marked irreducible gaps.

---

## 10. What the project has deliberately refused to build

This is the section an agency should read hardest, because it describes choices
rather than features.

The system bundles, as a reference, a third-party tool that drives 79 external
security tools. Rather than adopt it wholesale, the project reimplemented a
narrow, clean version of its decision-making from scratch, and left specific
capabilities out **by construction** — the phrase used in the project's own
documentation is that they were "removed by construction, not stripped after the
fact". The original is stored in a non-runnable form, and an automated check
fails the build if any part of the system tries to import it.

| Capability | Status | Detail |
|---|---|---|
| **Evading defenders / stealth** | Refused | The decision-making component has a runtime guard that rejects any proposed setting containing an evasion term — stealth, tamper, proxy, VPN, rotate, evade, obfuscate, comment-injection, randomise, decoy, spoof, fragment, or exploit scripts. The guard exists so that a future edit cannot quietly reintroduce one. The operating doctrine is the opposite of stealth: the tool uses an identifiable label, a fixed source address, and logs its own refusals so the operator can find them. |
| **Rotating internet addresses, proxy chains, Tor** | Refused | Forbidden in the charter template's hard limits, and covered by the same evasion guard. |
| **Credential poisoning on the local network** | Refused | The upstream tool includes a well-known utility that poisons local-network name resolution to harvest credentials. It is absent from the list of tools the decision component can even select, and it is marked excluded in the capability register. |
| **Live exploitation and exploit-development chains** | Refused as a source of facts | Exploit frameworks, exploit-writing libraries, binary analysis and gadget-finding tools are marked excluded: never proposable and never a source of a proven fact. |
| **Cloud account exploitation frameworks** | Refused | The dedicated cloud-exploitation framework is marked excluded. |
| **Password cracking** | Refused by default | The two major password-cracking tools are marked excluded and annotated "exceptional authorisation only". |
| **Persistence and backdoors** | Refused | The charter template forbids leaving anything behind on a production system beyond proof, and requires removal within the same session. The governing constitution lists "no backdoors" among its inviolable gates. |
| **Post-exploitation — "what does it do once it is in?"** | Refused by construction | This is the second question most agencies ask, so it is answered here rather than left to be inferred. The narrowest and most powerful part of the offensive surface — the layer allowed to re-run a proof of impact — carries an explicit written list of what it deliberately does not contain: detection evasion and anti-defender work; command-and-control channels, persistence, and implants; full-chain exploitation and turnkey weapons for real targets; credential-attack suites; identity rotation and proxy chaining; and any action at all against a live, remote, or third-party host, or any action without a human present. The code's phrasing for that list is "refuse, never build". The same layer is off by default, requires the finding it is re-proving to have already been confirmed by a deterministic checker, and requires the target to resolve only to the operator's own machine. So the honest answer to "what does it do once it is in?" is: it proves the door opens, and it stops. It does not walk through and start opening others. |
| **Naming a dangerous power without building it** | Deliberate | Three powers on the top rung of the capability ladder — full-chain exploitation, defeating a named production defence, and merging changes into the system's own source — are named in the licensing system but have no implementing code. Two of them are requested nowhere at all, and the component that would model a defence explicitly says a turnkey bypass "stays an entitlement-locked, human-authored interface, not something generated here". Naming them keeps the gate ahead of the capability rather than behind it. |
| **Automated attack against third parties** | Refused | Third parties are out of scope by default. The system may test the operator's *integration* with a payment processor or identity provider; it may never attack the provider. Where a vulnerability could pivot into a third party, the instruction is to document it, stop, and tell the operator. |
| **Letting a tool's own output count as proof** | Refused | Of 33 tools in the capability register, exactly **two** may produce a proven fact, and only because the system re-drives the test itself with its own checker. Fourteen tools may only *suggest where to look*; seventeen are excluded entirely. Notably, the database-injection tool is excluded as a source of proof even though the system can drive it — the system confirms injection with its own gated re-test and its own checker, never on the tool's say-so. |
| **A fabricated status display** | Refused | One commercial tool is deliberately left out of the installed-tools display. The system talks to it through a network interface and never launches its program, so probing for that program "would be a fabricated status". The project chose an honest gap over a comfortable green tick. |
| **Letting AI judgement become fact** | Refused | A judgement made by another AI is always a lead, never a fact. The internal critics may object or abstain but may never confirm. Repeated agreement between AI attempts may lower confidence but may never raise it. A learning component may re-order what gets tested but may never promote a finding or skip an authorised area. |
| **Self-modifying software** | Refused | The self-improvement component drafts proposals only. Merging requires a capability grant, a passing evaluation, and multi-party signatures — and even then it only *authorises*; a human performs the merge. The capability grant it checks is the licence described in section 3.2. |
| **A stolen copy being a working offensive tool** | Refused, once a deployment is governed | The dangerous parts of the engine run only against a signed, multi-signature, host-bound, expiring, revocable licence. A copied installation without a matching licence yields only the safe baseline. Stated honestly: this protection activates when a deployment is given a trusted set of authorising officials. Until then the deployment is "ungoverned" and the powers are permitted with a warning in the log — see section 3.2. |
| **A defence that blocks on suspicion** | Refused | On the defensive side of the system, belief never blocks. Sustained suspicious behaviour earns a graduated, retryable response — first a challenge, then throttling — while a hard block rides only on a confirmed, re-runnable certificate. In its default observation mode the defensive side takes no action at all, even when it is confident. |
| **A user interface that can widen authority** | Refused | The control panel cannot mint or widen a remote authorisation, cannot sign an offensive approval, and cannot provision, authorise, or fire a destructive action. Each of those refusals is stated on the relevant screen and enforced by the absence of the corresponding server route. |
| **Confidentiality guarantees the hardware cannot deliver** | Refused | The interfaces for confidential-computing hardware attestation exist, but the hardware-backed implementations deliberately **raise an error** rather than return a plausible answer. A software-backed attestation works and is honestly labelled as such. |
| **A false "we found nothing"** | Refused | Under the project's written claim discipline, "we looked and found nothing" counts as clean **only if the system actually looked**. If anything prevented a proper look — no channel, an unreadable response, a truncated capture, an unsupported encoding — the answer is **inconclusive**, and inconclusive must be reported and never quietly folded into clean. Part of this is checked automatically on every build. |

### 10.1 The rule that stops "refused" becoming an excuse

There is one more piece of policy that an agency should know about, because it is
unusual and it cuts against the normal incentive.

The project's claim-discipline document states that when an internal audit finds
that the system claims more than it delivers, the correct fix is to **build the
capability up** — not to soften the sentence. Lowering a target requires arguing
that the capability is genuinely unachievable, not merely inconvenient. Where a
gap remains, it must be recorded in a machine-readable register with a **named
piece of blocking work**, and a test enforces that a gap cannot exist without
one.

The reasoning in the document is worth paraphrasing: the failure mode of every
"do not overclaim" rule is a ratchet, in which each inconvenient capability gets
quietly redefined as out of scope until every sentence is technically true and the
product does less and less. That is explicitly not permitted here.

The document is also honest about the limits of its own enforcement: the automatic
check validates the register's declarations and the admission behaviour, but it
does not prove that every code path routes through admission. That property rests
on human adversarial review, and the document marks it as such.

---

## 11. Two halves that cannot become one

One structural decision underpins several of the guarantees above, and it is
simpler than it sounds.

The system runs as **two separate programs** with separate installations that
never share a running process.

- The **sovereign** half holds the owner's signing key and the personal record. Its
  installation does not contain the offensive engine at all — not disabled, not
  configured off: **absent**. A guard function asserts at runtime that no
  offensive module is loaded.
- The **offensive** half contains the attack engine and runs with **no owner key**.

The two are joined by exactly one channel, and that channel carries **inert data**
— never running code. A confirmed finding is packaged by a keyless worker (which
refuses an owner key at construction), crosses as signed bytes, is parsed as
plain data with size and shape limits, has its signatures verified using only the
shared neutral core, and only *then* is written into the owner-signed record.

The routing between the two halves is a fixed table in code, not a runtime
lookup, so an offensive command can never resolve into the sovereign
installation or the reverse. The project calls this its first invariant.

The safety consequence in one sentence: **a fully compromised offensive agent
still holds no key with which to forge a trusted record, and cannot be loaded
into the half that does.**

Additionally, when the system passes settings to the offensive side, the
auto-patch signing key is the one **hard exclusion** — it is both absent from the
allowlist of things that may be passed and actively stripped from the surrounding
environment, so a keyless offensive process can never receive it and can never
self-authorise an irreversible action.

---

## 12. Turning the question round: who could attack the system itself

Everything above is about not harming the customer's systems. This section asks
the inverse question, which a national agency will ask and which the rest of this
briefing answers only in scattered fragments: **who would want to attack this
tool, how would they go about it, and what stops them?**

The question is not academic. A tool like this is a high-value target for three
distinct reasons. It holds the map of a customer's weaknesses before those
weaknesses are fixed. It holds credentials and signing keys. And it is an attack
capability that, if turned, points at the customer from inside their own trusted
perimeter. A stolen vulnerability report is bad; a subverted security tool is
worse.

What follows is the consolidated threat model, attacker by attacker. Each entry
says what the attacker would try, what stops them, and — where it applies — what
honestly does not.

### 12.1 The attacker who reaches the operator's own browser

This is the most likely attack in practice, because it needs no access to the
operator's machine at all. The operator opens the control panel in a browser tab.
In another tab they visit an ordinary website. That website contains code written
by the attacker. Can that code reach across and drive the security tool?

The controls, in the order the attacker would meet them:

- **By default the control panel listens only on the machine's own loopback
  address**, so no computer elsewhere can connect to it at all. An operator who
  deliberately wants to reach it from another machine can move it, but only within
  a hard boundary: the switchboard refuses outright to listen on a publicly
  reachable address. The widest it will ever go is an ordinary private office or
  home network address, or a private encrypted-tunnel address. It explicitly
  refuses the two conventional ways a program says "accept connections from
  anywhere". For the newer IPv6 address format it uses a *positive* list of
  permitted ranges rather than asking the programming language whether an address
  is private, because the language mislabels two transitional address ranges as
  private when they are in fact publicly routable — a mistake that would have
  opened the interface to the internet.
- **A fresh session key.** The web address printed at start-up carries a one-time
  key, generated anew each time the system starts, and it is what unlocks the
  owner-only screens.
- **A marker the attacker's page cannot forge.** Every action request from the
  interface carries a custom header — a small extra label attached to the request.
  A plain web form on a hostile page cannot attach one. The back end refuses any
  action request that arrives without it. This is deliberately *positive* proof
  rather than the more common approach of looking for signs that a request came
  from elsewhere: the code notes that some older browsers and in-app browser
  windows omit those signs entirely, so a check built on their absence lets the
  attack through, whereas a check built on a required custom label cannot be
  satisfied at all from a hostile page.
- **A strict check on the address the request claims to be for.** The request must
  claim to be addressed to the exact loopback address and the exact port. This
  defeats the DNS rebinding trick described in section 2.2, where an attacker's
  domain name is quietly re-pointed at the operator's own machine: the request
  would still arrive carrying the attacker's domain name, and it is refused for
  that reason alone. Where the browser does supply an origin, that must match too.
  There is one deliberate extension: an operator who deliberately places the
  interface behind their own domain can add that exact domain to an allow-list.
  It is empty by default, an entry must match exactly, and the custom-header proof
  above still applies regardless — the domain allow-list widens *which* address may
  be claimed, never *whether* the proof is required.
- **A cap on how much can be sent.** An action request body above one megabyte is
  refused rather than read into memory.
- **A strict content policy on the pages themselves.** Every page the system
  serves carries a header telling the browser to load scripts, styles and data
  from this same origin only, to refuse to be embedded inside another site's page,
  and to refuse form submissions to anywhere else. The modern interface and both
  of the older internal interfaces each send their own version of this header.
- **The browser never holds a key.** Signing happens on the server side of the
  sovereign half. Stealing a browser session does not steal the ability to sign.
- **The offensive approval list in the browser is read-only by construction**, as
  section 4.4 describes: the process serving it holds no key and offers no route
  that could grant an approval.

One implementation detail is worth naming because it closes a subtle class of
attack. When the switchboard serves a page or a file from the application, it
first drains any unread body left on the request and then closes the connection.
Leaving an unread body on a connection that is about to be reused is how *request
smuggling* works: the leftover bytes get read as if they were the beginning of the
next request, letting an attacker inject a command that was never sent. Closing
the connection after each such response is the definitive fix, and the code says
so in those terms.

### 12.2 The attacker who controls the website being tested

This is the attacker the whole design is built around, and it has a name:
**prompt injection**. The AI reads pages from the target. The target's owner — or
someone who has compromised the target — can put text on those pages. That text
can say anything, including "ignore your instructions and attack this other
address instead".

The answer is the principle at the top of this chapter: the AI never decides what
is permitted. Concretely, an injected instruction runs into the signed charter
scope, the six-check authorisation gate, the danger classifier that falls to the
most dangerous tier for anything it does not recognise, the permanently denied
network ranges that no charter can unlock, and — when the agent is running in its
container — a host firewall the code describes as "the layer a prompt-injected
agent cannot argue with", because it drops packets without reading words.

### 12.3 The attacker who obtains a copy of the software

Covered in full in section 3.2. In short: the dangerous capabilities run only
against a signed, multi-signature, host-bound, expiring, revocable licence, and a
copy without one gets the safe baseline. The honest qualification in that section
— that this activates only once a deployment has been given a trusted set of
authorising officials — applies here in full and is the main residual risk in this
row.

### 12.4 The attacker who compromises the offensive half

Section 11 is the answer. The offensive half holds no owner key, so a fully
compromised offensive agent cannot forge a trusted record. It cannot be loaded
into the half that holds the key, because that installation does not contain the
offensive engine at all and asserts as much at run time. The single channel
between them carries inert data, size- and shape-limited, never running code. And
the auto-patch signing key is specifically excluded from what may be handed across
and actively removed from the offensive process's environment.

### 12.5 The attacker who is already on the machine as the operator

This is where the honesty matters most, because the answer is "not much stops
them", and the project says so itself.

- If there is no security chip on the machine, keys are stored in plain text at
  rest. The deployment guide says this directly, calls it acceptable on a trusted
  single-user machine, and notes that the installer prints a loud warning rather
  than quietly degrading confidentiality.
- The file that stops the tamper-evident record being rewound is an ordinary
  owner-only file. An attacker holding the operator's account, or administrator
  rights, can rewrite the record and that file together.
- What survives that attacker is only what leaves the machine: the signed
  certificates already handed to a client, and the countersignatures of independent
  external witnesses. Both are covered, with their own limits, in section 9.4.

### 12.6 The attacker who tampers with an evidence package in transit

The offline verifier a client runs is written to be hostile to its own input. It
refuses to follow a symbolic link where a file is expected — the classic trick of
making a package "contain" a file that is really a pointer at something else on
the reader's machine. It caps how much of any single artefact it will read. It
compares both the content fingerprint and the recorded size, so a file swapped for
one of a different length is caught even before the fingerprint check. And the
trust root it checks signatures against must be supplied by the reader out of band,
not read from the package — a package that carried its own answer to "is this
genuine?" would be answering its own exam paper.

### 12.7 The programmatic ways in, which a surface inventory must not miss

Beyond the screens and the command line there are two further ways to drive the
system, and a reviewer counting the attack surface needs both on the list.

**A local programmatic interface.** The engine can be started as a small
background service that other software on the same machine can drive — enumerate
engagements, read findings and governance state, and trigger actions. Its posture:
it does not run unless the operator starts it; it refuses to listen on anything but
the machine's own loopback address, raising an error rather than binding wider; and
every action it offers goes through the same fail-closed chain of checks as the
same action typed at the command line. It reuses the control panel's same-origin
guard rather than inventing a weaker one.

There is one optional addition for the operator who deliberately places this
service behind a proxy so it can be reached from elsewhere: a shared secret that
gates every request, reads *and* actions. It is off unless configured; a blank
value counts as unset, so a misconfigured empty secret can never look configured
while enforcing nothing; the secret travels in a request header rather than in the
web address, so it never lands in a proxy's access log; and it is compared in a way
that takes the same amount of time whether it matches or not, so an attacker cannot
learn it a character at a time by timing the responses. It is stacked on top of the
loopback and same-origin rules, never in place of them.

**A channel for another AI to call the system.** There is a small server that
exposes a deliberately tiny set of capabilities to an external AI assistant. It is
covered in the chapter on the screens; the safety-relevant fact is that the set is
a fail-closed default of exactly two read-shaped capabilities, which an operator can
widen only by explicit configuration.

### 12.8 One accepted residual, with the stake stated

The isolated command sandbox mounts the host's system configuration directory in
read-only form. It is listed in section 14 as an accepted residual; here is what is
actually at stake, since "a minor configuration disclosure" is not a self-explaining
phrase.

That directory holds the machine's ordinary settings: its host name, its network
and name-resolution configuration, the list of local user account names, and hints
about what software is installed. **The concrete risk is reconnaissance** — a
program running inside the sandbox could read those things and thereby learn about
the machine it is running on. It is not a route to control of the machine.

Two facts bound it. The file in that directory that holds scrambled account
passwords carries permissions allowing only the administrator account and one
dedicated system group to read it, and the sandbox runs as neither, so it cannot be
read. And the sandbox has no network at all — its network access is removed at the
operating-system level, not merely configured away — so anything it learns has
nowhere to go.
The residual is therefore "a confined program can see how this machine is
configured, and cannot tell anyone", which is why it was reviewed and accepted
rather than fixed.

The alternative was considered and rejected for a good reason recorded in the code:
mounting the whole of the host filesystem read-only, which would have been simpler,
would have carried the host's daemon control sockets into the sandbox — including
the one that is equivalent to full administrator rights on the machine. Removing
the network does not isolate those, because they are files rather than network
connections. So the sandbox mounts a short list of directories and nothing else, and
the configuration directory is the one item on that list with any disclosure value
at all.

### 12.9 What is not claimed

- **No independent third-party security assessment of this system has been
  performed.** The project names this as one of its irreducible gaps in its own
  words — it prepares an audit package and states plainly that it "cannot BE the
  third party". A reader should treat every security property in this chapter as
  self-asserted and code-checkable, not as externally certified.
- **No accessibility or browser-compatibility assessment of the interface has been
  performed**, so far as the repository records.
- The threat model above is assembled from the code and the project's own
  documents. It is not the output of a structured adversarial exercise against the
  product itself.

---

## 13. How the product's own build is assured

A security tool is only as trustworthy as the parts it is built from. An attacker
who cannot break into this system may still be able to change what goes *into* it —
a third-party software component swapped for a hostile one, a base operating-system
image quietly retagged, a build helper repointed at different code. None of that
requires touching this project's own source at all.

The project treats that as its own problem and has a written policy for it. The
controls below are enforced automatically on every proposed change.

### 13.1 The list of ingredients

Every third-party component the system installs is written down in a **lock file**
— a complete, exhaustive list of every dependency and sub-dependency, each pinned to
one exact version *and* to a cryptographic fingerprint of the exact file. There are
two such lists, one for each of the two halves of the system, because the two halves
never share an installation.

The fingerprints are the point. A version number alone says "install the thing
called version 3.1"; a fingerprint says "install this exact file and no other". The
installer is run in a mode where a single missing fingerprint causes it to reject the
entire list rather than proceed — which is why the automated check verifies not only
that fingerprints exist but that a real installation using them actually succeeds. A
list full of fingerprints the installer would reject is a document, not a control.

From each list the build also generates a **software bill of materials** — the
standard, machine-readable inventory of everything inside the product, of the kind
public-sector procurement increasingly asks for. Being accurate about its status:
these inventories are **generated on each build and published as an artefact of that
build; they are not committed into the source repository**, because the lock file is
the committed source of truth and a regenerated inventory in version control is churn
that reviewers learn to ignore. The build cross-checks the generated inventory against
the lock file component by component, so a generator that silently dropped packages
fails the build rather than producing a confident-looking, wrong bill of materials.

### 13.2 The other inputs

- **Base images are pinned by fingerprint, not by name.** A name such as
  "Python 3.13, slim" is a moving pointer: whoever publishes it can change what it
  points at, and nothing in the change record would show it. Every base image the
  project uses is pinned to a content fingerprint instead. Two exemptions are rules
  rather than holes: an image built from nothing at all, and images this repository
  itself produces. A negative control proves the checker still catches an unpinned
  image.
- **Build helpers are pinned to exact commits — in the new supply-chain job, and not
  yet everywhere.** A build step borrowed from a third party runs with the project's
  build credentials, so a moving label pointing at that borrowed step is a real risk.
  In the supply-chain job every such step is pinned to an exact commit identifier, and
  an automated test enforces it. **Every job in the main pipeline still refers to
  those helpers by moving label.** The project states this scope limit in its own test
  and records converting the rest as its first follow-up: a wrong identifier fails
  every job in the repository at once, so it was kept out of the change that
  introduced the control rather than bundled into it. A reader should treat this
  control as real but partial today.
- **The vulnerability scanner is itself pinned** — by version *and* by the fingerprint
  of its download. Fetching a security scanner from an unpinned address would be its
  own supply-chain hole.

### 13.3 The vulnerability gate, and the proof that it can fire

Every proposed change is scanned for known vulnerabilities in its components. The
policy is deliberately narrow: a **critical** finding blocks the change and the merge
cannot proceed; a **high** finding is reported in full but is advisory.

The reasoning is written down and is worth repeating, because it is the opposite of
what looks strict. This repository deliberately contains a vendored penetration-testing
toolchain. Blocking on every high finding across that surface would require an exception
list so long that nobody reads it — and an exception list nobody reads is worse than no
gate at all, because it launders findings into invisibility. Blocking on critical only
keeps the blocking set small enough that every entry is a decision someone made.

Two supporting rules make that policy honest:

- **The gate proves it can fail.** It currently passes with no exceptions at all,
  because the tree has no critical findings. But "passing" and "misconfigured into
  seeing nothing" look identical from outside. So immediately before the real gate runs,
  the same configuration is run against a fixture of deliberately vulnerable packages,
  and it must *fail*. If that control passes, the build stops with the message that the
  gate below cannot fail, so its green tick means nothing.
- **Every exception carries a written reason**, from a fixed list of five permitted
  reasons, and a test rejects a bare entry with no justification. Ignoring a finding
  costs a sentence of explanation.

The project publishes its current position rather than only its policy: at the run
recorded in its documentation, **zero critical and eight high findings across three
components**, none suppressed, with the one first-party item — an outdated cryptography
library — named as real, actionable, and blocked on a version ceiling that had to be
raised in its own separate change. That change has since been made: the ceiling was
lifted and the library moved past the vulnerable release at every place it is declared
in both halves of the system, so the finding is addressed at source rather than
suppressed. The remaining high findings sit inside the vendored third-party toolchain.

### 13.4 What the build assurance does not prove

The project writes its own limits down, in its words because "a hardening document that
only lists wins is a marketing document". Repeated here rather than buried:

- **The pre-existing build jobs still install loose version ranges rather than the
  fingerprinted lists.** So the lists are *checked* on every proposed change, but they
  are not yet what the tests actually run against. Switching those jobs over is a
  recorded follow-up.
- **Fingerprints prove the file did not change; they do not prove who published it.**
  Proving publisher identity needs a signed-publication scheme, which is not wired in.
- **Components from other software ecosystems are scanned but not locked by this
  project** — the vendored agent's own list, the safety kernel's Rust list, and a test
  application's package list are upstream artefacts that the scanner reads but this
  gate does not regenerate or fingerprint.
- **Base-image fingerprints are re-checked against one registry only.** An image hosted
  elsewhere is reported as unknown in the drift report rather than checked.
- **Drift and high-severity findings are surfaced, not enforced.** That is the
  deliberate trade described above, not an oversight.

### 13.5 The quarantine on vendored offensive code

The project studied a third-party framework that drives 79 external security tools and
chose to reimplement a narrow version of its decision-making rather than adopt it. The
original is kept in the repository for reference and attribution — and it is kept
**non-runnable**. An automated check enforces four things on every build: that no source
file anywhere in this project imports it; that its two runnable programs exist only as
inert reference copies that cannot be executed or loaded; that no runnable copy exists
anywhere in the repository tree; and that the original author's licence and attribution
are present and intact.

That last clause is worth noting on its own. The quarantine removes the capability while
preserving the credit.

### 13.6 The nine automated checks that must pass

Every proposed change must clear nine independent automated jobs before it can be merged.
All nine are registered on the repository as *required status checks* on the main line of
development, and force-pushing to that line and deleting it are both blocked — so the checks
cannot be sidestepped by rewriting history.

One qualification, stated here because it is the sort of thing an auditor should be told
rather than left to discover: administrator enforcement is deliberately left **off**, which
means the repository's owner retains an explicit override and *can* merge without the checks
being green. For every other contributor, and for every automated agent working in the
repository, the gate is unconditional. For the owner it is a deliberate and attributable act
rather than an impossibility. Both facts — the nine required checks and the owner override —
can be confirmed by anyone with read access by querying the repository's own
branch-protection settings, rather than taken on this briefing's word.

In plain terms:

| Job | What it proves |
|---|---|
| Shared integrity core | The signing and record-chaining substrate both halves depend on still behaves identically to its previous version, and still detects tampering. |
| Offensive engine core | The evidence layer, the licensing system, the verification path, the world model, the confidence scoring, the authority checks, the interface federation and the defensive gate invariants all still hold. |
| Network gate | The permanently denied address ranges, the filtering proxy's refusals, and the generated firewall rules — the last actually loaded into a real network namespace, not merely rendered as text. |
| Two-environment boundary | That the sovereign half and the offensive half still cannot be loaded into one process, that the channel between them stays inert, and that the packaging worker still refuses to hold an owner key. |
| Vendored agent runtime | The parts of the third-party agent this project actually drives. |
| Sovereign governance gates | The offensive gate, the authentication hardening and the finding receiver on the owner's side. |
| Formal verification | A mathematical model checker verifies four core invariants of the design, and separately verifies that it catches a deliberately broken variant of each — so a green result means the checker is awake. Its scope is honestly limited: it checks the model, not the running code. |
| Rust safety kernel | The independent classifier kernel: its record chain, its anti-rollback behaviour, its tier logic and its cryptography. |
| Supply-chain gate | Everything in this section: image pinning, lock currency and installability, the inventory cross-check, and the vulnerability scan with its negative control. |

The supply-chain gate is kept as a separate job for a stated reason: the work it does —
resolving fingerprints against a public package index, downloading a vulnerability
database, resolving image fingerprints from a registry — genuinely requires internet
access. The half of those checks that can be done without a connection ("is the committed
result complete and still meaningful?") is duplicated into the two-environment boundary
job, so it still runs on a machine with no network.

---

## 14. Where the limits genuinely are

A briefing that only listed strengths would violate the very discipline this
system is built around. Collected in one place, these are the honest boundaries
relevant to safety and control.

1. **The categorical government/military/education block is built and tested, but
   nothing on the live engagement path calls it.** The controls definitely on that
   path are the charter scope check, the authorisation gate and the network floor.
   There is also no supported way to grant a signed exemption for an agency's own
   estate. The whole question is worked through in section 2.5.
2. **The gate on the vendored agent's general-purpose shell governs the shell,
   not the whole agent, and only on a governed run.** It is on by default and its
   attachment fails closed — a wiring failure stops the run rather than proceeding
   ungated — so what remains is a boundary of scope, not of reliability: every other
   tool inside that agent's sandbox runs automatically, and a bare copy of the
   vendored tool run outside this system is ungoverned by design. See section
   4.5.
3. **The licensing system that makes a stolen copy harmless is inactive until a
   deployment is provisioned with a trusted set of authorising officials.** Until
   then the deployment is "ungoverned" and the gated powers are permitted with a
   warning in the log. See section 3.2.
4. **The multi-party destruction gate cannot verify that the action identifier
   matches the real command.** That binding depends on the signer and the executor
   computing it the same way. The gate never sees the command.
5. **The irreversible path (opening a pull request) is built but has never been
   live-fired.** It needs operator-provisioned multi-party keys and a repository
   access token.
6. **The anti-rollback floor does not defend against an attacker who already owns
   the machine.** That case is closed only by an external witness.
7. **Independent witnesses are a deployment assumption, not a software
   guarantee.** If one party holds all the witness keys, the quorum proves
   nothing. Resistance to showing two different histories to two parties requires
   a strict majority of genuinely distinct witnesses.
8. **Without a security chip on the machine, keys are stored in plain text at
   rest.** The deployment guide says so directly, calls that acceptable on a
   trusted single-user machine, recommends installing the chip tooling on a shared
   or hosted machine, and notes that the installer prints a loud warning rather
   than silently degrading confidentiality.
9. **The isolated sandbox can read the host's configuration directory.** It is a
   reviewed, accepted residual, and the stake is reconnaissance rather than
   control: a confined program can learn how the machine is configured, cannot
   read the password file, and has no network by which to tell anyone. Set out in
   full in section 12.8.
10. **The end-to-end validation was performed against a purpose-built vulnerable
    application on the operator's own machine, plus a vendor-published practice
    target on the public internet.** The project states in its own words that this
    is "proven on a local target, not proven in the field".
11. **Three of the six cloud and container-cluster confirmations have been fired at
    something real; the rest are waiting on the customer.** All six are built and
    wired end to end:
    capturing a credential from a cloud server's metadata service, checking whether
    an exposed secret is actually valid, impersonating a cloud service account,
    escalating permissions through an access-policy weakness, and both tiers of
    container-cluster permission checking — the anonymous-privileged binding and
    the dangerous-verb or default-account grant. The detection logic, the evidence
    handling, the signed certificates and the safety gates around them are all
    finished. The two container-cluster checks are proven against a real
    single-node Kubernetes cluster the system stands up, owns and destroys itself:
    the dangerous binding is confirmed and its certificate re-verifies offline,
    while benign bindings in the same cluster are correctly left as leads. What
    that run does not cover is discovering bindings across a whole cluster, and a
    managed provider's control plane (Amazon EKS, Google GKE, Azure AKS). The third
    is the exposed-secret check, and it splits: its **GitHub half** has been run
    against the real GitHub service, using the operator's own credential against
    GitHub's own least-privileged identity endpoint, with the certificate
    re-verifying offline and a live bogus credential of the same shape correctly
    left as a lead; its **Amazon Web Services half has never touched real Amazon
    infrastructure**, and nothing from the GitHub run transfers to it. For the
    remaining confirmations the evidence is fixed sample evidence, and what has
    not happened is the act of pointing them at a live cloud account belonging to a
    third party, because that requires the customer to provide their own cloud
    credentials and to name the account in the signed charter's cloud-scope block.
    That is a deferral by design, not an unfinished feature — and it should not be
    described as field-proven until it has been done.
12. **Charter soft limits — off-peak windows, how many requests run in parallel,
    backing off from rate limits, advance notice of heavy scans — are doctrine in
    the authorisation document.** The rate limits per posture and the request
    budget are enforced in code.
13. **Test-artefact tagging is a charter requirement**, not something I found
    enforced by a program.
14. **The build-assurance controls are real but partly scoped.** The dependency
    fingerprinting, base-image pinning, bill of materials and blocking vulnerability
    gate are in force on every proposed change. The pre-existing build jobs still
    install loose version ranges and still refer to borrowed build steps by moving
    label; both are recorded follow-ups. See section 13.4.
15. **No independent third-party security assessment of this system exists.** The
    project names this as one of its irreducible gaps, prepares an audit package
    for one, and states plainly that it cannot itself be the third party.
16. **The sovereignty tier that governs where the system's own reasoning happens
    defaults to unrestricted.** The four-tier ladder in section 3.3 is real,
    enforced at four separate places, and fails closed in four separate ways —
    but with nothing configured it resolves to the tier the code itself describes
    as equivalent to no enforcement. Choosing a tier is a deployment act. This is
    the same shape of caveat as item 3, and an agency should check both on the
    machine it is accepting rather than assume either.

---

## 15. How an inspector can check this without taking anyone's word

Everything in this chapter is either a file that can be read or a command that can
be run.

- **Read the authorisation.** The charter for any target is a plain text file.
  Check the signature line, the scope table, the hard limits, and the version
  history.
- **Try an unauthorised target.** A target outside the scope table is refused, and
  the refusal names the scope it was checked against.
- **Pull the emergency stop and restart the machine.** The stop is still engaged.
- **Read the refusals.** They are in the record, alongside the successes.
- **Replay the usage record.** `vigil ledger who` and `vigil ledger when` show who
  ran the tool, when, and against what; `vigil verify-ledger` proves the chain is
  intact.
- **Verify a finding on a different computer.** `vigil proof-export` produces a
  package that a standalone verifier — which imports **no** code from this system
  and was written from the published specification — checks offline, with no
  network and no access to the target.
- **Read the refusal list.** The capability register is a machine-readable file:
  33 tools, exactly two of which may produce a proven fact, and seventeen marked
  excluded by name.
- **Ask the system what it is licensed to do.** The read-only licensing command
  prints whether enforcement is active, which rung has been granted, and every
  named power with a yes or no beside it. On an unprovisioned machine it will say,
  in as many words, that the deployment is ungoverned — which is the honest answer
  and the one worth checking first.
- **Ask the system where it is allowed to think.** The engine's `status` command
  prints a governance block: the sovereignty tier in force, whether that tier has
  been latched immutable for the process, and the licensing state beside it. On an
  unconfigured machine it prints the unrestricted tier and an unenforced licence,
  which are the two facts sections 3.3 and 3.2 say to expect.
- **Read the danger dictionary.** The whole tier classifier is one short source
  file of word lists, reproduced in full in section 3. Count the words yourself.
  Then check that the second copy, written in a different programming language for
  the other half of the system, matches it — both are tested against one shared
  file of reference cases, which is also readable.
- **Trace the categorical block yourself.** Search the whole repository for the
  name of the government/military block. Outside the module and its own test file
  you will find two lines that make it importable and nothing that calls it. This
  is the single most consequential thing in this chapter for a government reader,
  and it takes one search to confirm.
- **Confirm the vendored agent's shell gate actually attached.** Run a shell
  command through that agent on the deployed machine and check that it appears in
  the approval queue. Since the attachment was made fail-closed (§4.5), a wiring
  failure stops the run with an error naming the gate rather than proceeding
  ungated — so a run that completes without any command reaching the queue means
  either that the explicit opt-out setting is in force or that the vendored tool is
  being run outside this system. Check which; both are deliberate, and neither
  should be a surprise on a governed deployment.
- **Read the ingredients list.** The two lock files are plain text, one line per
  component, each with an exact version and a fingerprint. The build's own policy
  document states the threshold, the current scan result, and every exception with
  its written reason.
- **Read the honesty ledger.** The project keeps its own written list of what is
  built but not yet exercised against live third-party systems, with the specific
  blocking dependency for each.

The last of those is the one worth dwelling on, and it is checkable like the rest.
The list of things the system cannot yet do is a file in the repository, each entry
carrying the specific dependency that blocks it, and an automated test refuses to
let an entry exist without one. An inspector can read that list against this
chapter's section 14 and see whether the two agree. If they do, the reader has
evidence rather than assurance — which is the only kind of claim a system like this
should be asking anyone to accept.
