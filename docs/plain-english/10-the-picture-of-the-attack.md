# The Target Knowledge Graph: Building A Picture Of The Attack

## 1. Why the system draws a map at all

Almost every security testing product finishes its work by handing over a list.
The list says things like "this web page mishandles input", "this cloud account
is configured too loosely", "this software component is out of date". Every item
on the list may be perfectly accurate. And yet the list cannot answer the
question a minister, a permanent secretary, or a chief information officer
actually asks:

> *If someone came after us tomorrow, what would they actually get to?*

A list of broken locks does not tell you which room the intruder ends up in. For
that you need a floor plan. You need to know which doors open onto which
corridors, which corridor leads to the room holding the citizen records, and
which single door — if you fixed only that one — would cut the records room off
from the street entirely.

The system builds and maintains that floor plan. Inside the software it is called
the **world model**.[^1] Its own design note describes its purpose in one
sentence: to answer *"given what we have observed, what is now reachable, and by
what explainable route?"*

The map holds the machines, the network zones, the web pages and interfaces, the
databases and storage buckets, the cloud resources, the user and machine
identities, the credentials, the live logged-in sessions, the defensive controls,
and the confirmed weaknesses. It holds how they connect. Confirmed problems are
pinned onto it. The system then works out, step by step, where an attacker
standing at any one point could travel to, what that would expose, and which
single repair would do the most good.

This chapter explains that map in ordinary language: what is on it, where each
entry comes from, how chains are worked out, how the map is kept honest, what the
operator sees, and — stated plainly — which parts have been exercised against
live third-party systems and which have not.

A note on vocabulary. A small number of words are used throughout this briefing in
a strict sense. They are used the same way here, and it is worth fixing their
meaning before the detail starts.

- An **automatic test** is a small, fixed program that looks at saved evidence and
  answers one narrow question, always the same way. It has no intelligence, it
  cannot reach out over the network, and it cannot read the clock. The software's
  own name for it is an **oracle**, and that word appears in the code and on some
  screens; this chapter says "automatic test".
- **Deterministic** means: the same input produces the same answer, every time, on
  any machine. It is a recipe, not a chef — no judgement, no mood, no
  improvisation.
- **Fail-closed** means: if a check cannot be completed — an error, a missing file,
  no answer at all — the result is "no". Like a drawbridge held up by power: cut
  the power and it falls shut.
- A **LEAD** is a suspicion. It is worth attention. It has not been proved.
- A **FACT** is a claim that an automatic test actually confirmed over evidence the
  system captured itself, and that anybody else can re-run over that same retained
  evidence, offline, without the system present.
- **Provenance** is the recorded history of where a piece of information came from
  and how it was obtained. Every single entry on this map carries its own.
- **The signed record** — the software calls it the *spine* — is the running
  journal of everything that happened during an engagement. Entries can be added to
  it; they can never be edited or erased. Section 5 explains it and why the map is
  built from it and from nothing else.

The distinction between leads and facts has its own chapter. What matters here is
that the map keeps the two apart at every point, and never lets one quietly turn
into the other.

---

## 2. The two building blocks: things, and connections between things

A map of this kind is built from exactly two ingredients. This chapter calls them
**pins** and **arrows**. The software calls them **nodes** and **edges**, and those
are the words that appear in the code and on the screens. The two pairs of words
mean exactly the same thing; where a screen or a report is quoted directly in this
chapter, its own wording is left alone.

A **pin** (in the software, a *node*) is a *thing*. A server. A login account. A
database. A leaked password. A confirmed vulnerability. Think of it as a pin
pressed into the floor plan, with a label saying what sort of pin it is.

An **arrow** (in the software, an *edge*) is a *statement one thing makes about
another*, and it always has a direction. "This machine can reach that service."
"This account can take on that role." "This password works on that account." Think
of it as an arrow drawn between two pins, with a word written on the arrow saying
what kind of relationship it is.

That is the whole vocabulary. Everything else in this chapter is built from pins
and arrows.

The set of pin types and arrow types is deliberately small and fixed. The design
note explains why the system does not simply adopt an off-the-shelf schema:
existing attack-graph models are either network-only (they model which machine
can talk to which, but know nothing about identity or cloud permissions) or
identity-only (they model who can assume which role, but know nothing about
network reach or web weaknesses). Real compromise crosses all three. The example
the code itself gives is the archetype: a web page leaks a credential; the
credential works on an account; the account can take on a cloud role; the cloud
role sits in front of a database.

### 2.1 Every kind of "thing" the map can hold

There are twenty-two, and they fall into two families. The first twelve are the
*attack* vocabulary — the things an intruder moves between. The remaining ten are
the *intelligence* vocabulary — the things reconnaissance discovers about an
organisation's external footprint.

**The attack vocabulary**

| Type | In plain words |
|---|---|
| Host | A machine or virtual machine. |
| Service | Something listening for connections on a machine (a web server, a database engine). |
| Endpoint | One specific address or function within an application — a single web page or programming-interface call. |
| Web application | A browser-facing application taken as a whole. |
| Datastore | A database, a storage bucket, or a secret store — a place where data lives. |
| Cloud resource | An object in a cloud account whose access is governed by cloud permissions. |
| Network segment | A network zone, subnet, or trust boundary. |
| Principal | An identity that can act: a person's account, a role, or a machine account. |
| Credential | A secret that proves you are a principal — a password, a key, a token. |
| Session | A live, already-logged-in session. |
| Control | A defensive measure: a web application firewall, a login requirement, multi-factor authentication. |
| Finding | A confirmed weakness. |

**The intelligence vocabulary**

| Type | In plain words |
|---|---|
| Domain | An internet name, such as an organisation's website address or one of its sub-addresses. |
| Certificate | One specific digital certificate presented by a server, identified by its fingerprint. |
| ASN | An "autonomous system" — a large block of internet address space operated by one organisation. |
| Netblock | A range of internet addresses. |
| Organization | The owning organisation or registered holder of an internet asset. |
| Identity | A publicly discoverable persona or email address. This is deliberately *not* the same type as a Principal: it is an open-source-intelligence observation, not a proven login actor. |
| Application | A non-web application. |
| Package | A software component an application depends on — the supply-chain building block. |
| Vulnerability | A publicly published security advisory about a piece of software. The code is explicit that this is a **lead from threat intelligence, never a confirmed finding**. |
| Indicator | A threat-intelligence marker that is not itself an asset — for example a file fingerprint. |

Three of those entries use words a reader may not have met.

- A **digital certificate** is the electronic credential a server presents to prove
  it is who it claims to be — the thing sitting behind the padlock symbol in a
  browser. Its **fingerprint** is a short code computed from the certificate's
  whole contents; change one character of the certificate and the code changes
  completely, so the fingerprint identifies that exact certificate and no other.
- A **published security advisory** is a public notice that a particular piece of
  software has a known flaw. The best-known register of these is the
  **Common Vulnerabilities and Exposures** catalogue, usually abbreviated to
  **CVE** — an international public list that gives every disclosed software flaw
  its own reference number. The system records these advisories, but only ever as
  suspicions.
- A **file fingerprint** is the same idea applied to a file: a short code computed
  from its contents, used to recognise a known-bad file wherever it turns up.

The separation between "Vulnerability" and "Finding" is not cosmetic. A published
advisory saying a component *may* be affected is a lead. A Finding is something
this system proved on this target. They are different pin types so that no query
can accidentally return one when it meant the other.

### 2.2 Every kind of "connection" the map can hold

There are twenty-four, in four families.

**Movement, trust and identity — the arrows an attacker can actually walk along**

| Connection | In plain words |
|---|---|
| Reachable from | The second thing can be reached from the first (over the network, or by a call). |
| Trusts for | The first thing trusts the second for some stated purpose. |
| Has grant | The first (an identity) holds a permission over the second (a resource). |
| Member of | The first (an identity) belongs to the second (a group or role). |
| Can assume | The first (an identity) can take on the second identity. |
| Valid on | The first (a credential) authenticates as the second (an identity). |
| Authenticates to | The first (an identity or session) logs in to the second. |
| Session on | The first (a live session) is established on the second. |

**What the attacker has actually achieved**

| Connection | In plain words |
|---|---|
| Owns | The attacker controls this thing. |
| Holds | The attacker possesses this credential, token, or session. |
| Reached | The attacker has got as far as this service, page, or network zone. |

**Annotation — arrows that describe, but that nobody can walk along**

| Connection | In plain words |
|---|---|
| Control protects | A defensive control sits in front of this thing. |
| Evidences | A confirmed finding is evidence about this thing. |

**The reconnaissance and supply-chain picture**

| Connection | In plain words |
|---|---|
| Resolves to | This internet name points at this address. |
| Presents cert | This server or name presents this digital certificate. |
| Announces | This large address-space operator announces this address range. |
| Hosts | This machine or address range hosts this service or application. |
| Runs | This machine or service runs this application. |
| Observed on | This asset was seen in this source or context. |
| Asset owns | This organisation or address-space operator owns this asset. This is deliberately a *different* arrow from "Owns" above; the code note explains why in as many words — a reasoning rule keyed on ordinary ownership "would hallucinate attacker reachability from mere asset ownership". |
| Same as | Two references are believed to be the same underlying asset. |
| Co-hosted with | Two distinct assets share infrastructure. |
| Depends on | A component depends on this software package. |
| Affects | A published advisory names this package or application as affected. Again, this is a **lead**; a separate automatic test is what proves that a specific installed version genuinely falls inside an advisory's affected range. |

The distinction between "walkable" and "annotation" arrows is one of the more
important safety properties on the map, and section 6.2 returns to it.

---

## 3. Every entry on the map carries a label saying where it came from

A map is only as good as its sourcing. If a floor plan mixes surveyed
measurements with somebody's guess, and does not say which is which, it is worse
than no floor plan at all — because it invites confident decisions built on the
guess.

So every pin and every arrow on this map carries, permanently:

- **Where it came from.** A short **source label** pointing back to the specific
  observation, automatic test result, or signed certificate that asserted it.
- **How strongly it is believed.** A number between 0 and 1.
- **When it was first and last seen.** Not a clock time — see section 3.3.
- **A grounding tier.** A one-word classification of the *kind* of source.

### 3.1 The four grounding tiers

The grounding tier is worked out automatically from where the entry came from, by a
single piece of code that the rest of the system reuses — so "what counts as
proven" is defined in exactly one place, and cannot drift apart between one part of
the system and another.

| Tier | Meaning | What produces entries of this kind |
|---|---|---|
| **grounded** | An automatic test actually fired over saved evidence, or a signed evidence certificate exists. | The confirmation step of a scan; a signed evidence certificate; a finding that has been promoted to proven. |
| **intel** | Genuine information that was collected, or worked out from collected information — real, but not proof. | Background research on the organisation's public footprint; scanning and fingerprinting; conclusions reasoned out from other observations. |
| **ungrounded** | The artificial-intelligence component said so, or somebody assumed it, or the claim has since been **withdrawn**. Explicitly not a fact. | Output from the AI component; bare assumptions; published advisories; anything demoted after its proof stopped reproducing. |
| **unclassified** | The source does not match any of the above. | Anything else. |

Every entry's source is recorded as a short text label whose opening word is what
the classification reads.[^2] A technical reviewer can therefore check the tier of
any entry by eye, without running anything.

There is an optional **strict mode**. When it is switched on, an entry whose source
classifies as *ungrounded* has its belief forced down to a low floor (0.2)
regardless of how confidently it was asserted. In other words: in strict mode, a
confident-sounding machine-generated claim cannot enter the map at a high belief
merely because it sounded confident.

### 3.2 Two numbers, not one: the headline figure and the belief that can fall

Every entry carries two separate measures of belief, and the reason is worth
understanding, because it is a genuine piece of engineering honesty.

The first is a plain **confidence** figure. When the same fact is observed again,
this figure is reconciled to the **higher** of the two. Re-observing something
never lowers it. That is the right behaviour for a headline number — a fact seen
twice should not be believed less than a fact seen once.

But it has an obvious blind spot: a number that can only go up can never express
"we checked again and it did not hold".

So each entry also carries a second, statistical belief, accumulated from every
observation of that entry. A high-confidence re-observation pushes it up. A
low-confidence or failed re-observation pushes it **down**. Two figures are
derived from it:

- a **belief average** — the middle of the current belief;
- a **conservative lower bound** — the belief average, minus a margin reflecting
  how thinly evidenced it is.

The lower bound is the interesting one. Something believed strongly on the basis
of a single observation scores *below* something believed slightly less strongly
but corroborated many times. That is exactly the ordering a cautious analyst would
use, and section 9.3 shows where the system uses it to rank routes.

A useful ordinary-life comparison: the headline confidence is like a patient's
recorded diagnosis, which stays on the file once made. The statistical belief is
the running series of test results underneath it — and if the repeat tests come
back negative, the series says so, even though the recorded diagnosis is still in
the file.

### 3.3 The map never looks at the clock

This sounds like a technicality. It is not.

The map has no concept of wall-clock time. Instead, whoever writes to it supplies
a **sequence number** — a simple counter that only ever goes up. "First seen" and
"last seen" are counter values, not dates.

The consequence is that the map is **reproducible**. Feed the same record of
events in again and you get a byte-for-byte identical map, the same routes, and
the same rankings. Nothing depends on what time of day the analysis ran, or on any
element of randomness. An auditor, an oversight body, or a rival supplier can
rebuild the map from the same signed record and check that it comes out the same.
If it does not, something has been tampered with.

This "no clock, no randomness" rule runs through the whole subsystem: the graph
does not read the clock, results are ordered deterministically, and lists are
sorted by fixed keys so that ties break the same way every time.

---

## 4. How the map grows without ever forgetting

When the system asserts something the map already holds, the entry is **merged**,
not duplicated. Concretely:

- **Properties merge.** New details are added; details recorded earlier and not
  re-stated are kept. The map accumulates knowledge rather than overwriting it.
- **Headline confidence rises to the higher of the two** — and, a small but
  careful touch, the more confident assertion also donates its source label, so
  the surviving label names the *strongest* evidence rather than the most recent.
- **The statistical belief is updated** in the direction the new observation
  actually points, up or down.
- **The seen-window widens**: earliest stays earliest, latest stays latest.

One thing may never change: what a pin *is*. If the map already holds something as
a database and a later write claims it is a machine, the write is rejected as an
integrity error rather than silently accepted.

An arrow may also only be drawn between two things that already exist on the map.
The reason is blunt: inventing a pin merely so that a relationship has something to
point at would invent a shape for the organisation's estate that nobody ever
observed — a corridor drawn on the floor plan because a door had to lead somewhere.
If a relationship needs a pin that is not on the map, the relationship is refused,
and the pin is not conjured up.

---

## 5. Where the map comes from: the signed record, and nothing else

This is the structural safeguard that makes everything above trustworthy.

The system keeps an **append-only, signed record** of everything that happened
during an engagement — every observation, every action, every test result, every
confirmed finding. Entries can be added. They cannot be edited or deleted; a
correction is made by appending a new entry that supersedes the old one, and the
old one remains visible in the history. That record is the single source of truth,
and it has its own chapter.

The map is a **projection** of that record — meaning it is derived from the record
and only from the record, the way a photograph is derived from a negative. One
piece of code reads the record and writes the map. Nothing else writes to it. The
module's own documentation states the rule directly: *"Nothing an LLM or a tool
asserts reaches the graph except as a spine record; its veracity is re-derived,
never trusted."* In plain words: nothing the artificial-intelligence component or
any tool claims gets onto the map by claiming it. It must be written into the
signed record first, and its truth is worked out again from scratch rather than
taken on trust.

Four rules are enforced at that boundary.

**Confirmed means signed.** A finding becomes a *confirmed* entry on the map only
if its record is marked as a fact **and** carries both a non-empty pointer to
signed evidence **and** a signature reference. A record that merely *claims* to be
a fact, with no signed evidence behind it, is treated as a lead. The graph, in the
code's own words, "can never launder an unproven claim into a fact".

**Certainty is never manufactured.** If a record states its own confidence, that
figure is used as given. If it does not, the system falls back to a deliberately
conservative default: 0.9 for a grounded fact — *never* 1.0 — and 0.5, a coin
flip, for a lead. The comment explains the choice: it mirrors the reporting
layer's rule that a confirmed finding is 0.9, not 1.0.

**The whole projection rebuilds identically.** Records are applied in a fixed
total order and in two passes — all the things first, then all the connections — so
an arrow can never race ahead of the pins it joins. The same record therefore
always produces the same map.

**A withdrawal must itself be proven.** A record that retracts a previous claim
lowers the belief in it — but *only* if that retraction is itself backed by signed
evidence. An unauthenticated retraction of a proven fact is ignored. The code
states the principle in one line: *an opinion cannot un-prove a proof.* And the
retraction never deletes anything; the entry stays on the map for audit, with its
belief reduced.

A final defensive property: the projector is total. One malformed record is
skipped, not allowed to bring down the whole projection.

---

## 6. How a confirmed finding becomes part of the picture

### 6.1 The surface and the finding

When a scan produces a confirmed finding, two pins go onto the map: an **endpoint**
pin for the specific surface that was tested, and a **finding** pin for the
weakness itself. An "evidences" arrow is drawn from the finding to the surface.

The finding pin carries the weakness class, which automatic test confirmed it, the
confidence, and the identifier of the check that found it.

### 6.2 A finding, on its own, grants the attacker no movement

This is one of the most important design decisions on the map, and it is easy to
miss.

The "evidences" arrow is an **annotation**. It is not in the set of arrows a route
search is allowed to walk along. The comment in the projector spells out the
consequence: *"A finding cannot fabricate reach; the reach it enables must be
recorded as its own relation record."*

Put in ordinary terms: discovering that a door has a weak lock does not, by
itself, put you on the other side of the door. If the system is going to claim
that a weakness lets an attacker *move*, that movement has to be recorded as its
own statement, with its own evidence behind it. This closes a failure mode that
would otherwise be very easy to fall into — treating "we found a problem here" as
if it were "we are now inside".

### 6.3 The consequences of particular weaknesses are modelled explicitly

For weakness classes whose consequences are well understood, the system writes
those consequences onto the map deliberately, one class at a time, each labelled
with the finding that justified it. Where the description below says the system
"mints" something, it means it adds a new pin to the map — a thing the weakness
proves must exist, such as the database sitting behind a page that hands out its
contents.

- **Server-side request forgery** — the outsider can make the organisation's own
  server fetch an address of the outsider's choosing, so the server becomes an
  errand boy reaching places the outsider cannot reach directly. Such a finding
  marks the surface as one that fetches addresses on the attacker's behalf.
- **Broken access control** — the page hands over data without properly checking
  who is asking. (Two families of this have their own names in the trade:
  "insecure direct object reference", where changing a number in the address shows
  you somebody else's record, and "broken object level authorisation", the same
  idea in a programming interface.) Such a finding marks the surface as
  unauthenticated, mints the **datastore** sitting behind it, and draws a
  "trusts for" arrow from the surface to that store — because that is precisely
  what the weakness means: the surface hands out the store's contents without
  checking who is asking.
- **Deserialisation** — the application accepts a packaged-up block of structured
  data from outside and unpacks it back into live working objects. If the block
  is attacker-written, unpacking it can end up running the attacker's instructions
  on the machine. Such a finding marks the surface as processing untrusted
  structured data, and mints the **host** it runs on, with the host reaching the
  surface.
- A **disclosed private key** — the secret half of a cryptographic key pair, the
  part that is supposed never to leave the owner — found lying in public becomes a
  **credential** pin with an identity it is valid on, because a leaked key is a
  credential an attacker can simply pick up.

### 6.4 The six cloud and Kubernetes confirmations

The system also models the achieved effect of six cloud and container-platform
confirmations. All six are wired end to end. Of the four **cloud** ones, the GitHub
half of exposed-secret validity is proven against the **real GitHub service**, driven
by a repository script over a real network connection. The other three, and that same
capability's Amazon Web Services half, are proven offline against **recorded sample
data standing in for the real thing** — evidence files written to the exact shape a
real cloud account produces, kept on file and replayed through the same checks
whenever anybody wants to see the proof again. The
two **Kubernetes** ones are proven against a **real cluster**: a repository script
stands up a genuine single-node cluster that the system creates, owns and destroys,
plants known-dangerous and known-benign access rules in it, and adjudicates what the
real Kubernetes interface returns through those same checks.

One point of precision about the cloud sample data, because it is the sort of thing a
careful reader should press on. It was written for the purpose. It was not harvested
from anybody's live cloud account. The honest comparison is a laboratory proving its
instruments against a prepared reference sample of known composition: it establishes
that the instrument reads correctly, and it is not the same thing as having tested a
patient. For the two Kubernetes confirmations that comparison no longer applies —
there the laboratory grew a real specimen of its own and read that.

What makes that kind of proof worth something is the near-misses. Alongside each
sample that *should* make a check fire, the system keeps deliberately spoiled twins
that should leave it silent — for the metadata-credential case, for example: a
credential with no proof it ever worked, a credential whose confirming attempt
failed, a credential that came from somewhere other than the machine's own
credential service, and a meaningless block of data. Each of those silent controls
was itself put to the test by changing exactly one detail and checking that the
change *does* make the check fire. That matters: it shows a silent control is silent
because the check is discriminating, not because the check is asleep. The same
discipline is written into the offline proofs for the exposed-secret, the permission
escalation and the Kubernetes permission confirmations — and for Kubernetes it is
repeated against the real cluster, where the benign arrangements planted alongside the
dangerous one, including the namespace's own default identity bound to the built-in
`admin` role, correctly stay leads.

Section 17 states precisely what remains outstanding for these six, and why.

("Kubernetes" is the standard software used to run applications in containers
across a fleet of machines. Its "control plane" is the central interface that
administers the whole fleet; reaching it with administrative rights means
controlling everything it runs.)

| Confirmation | What is written onto the map |
|---|---|
| **Metadata credential capture** — a cloud instance's own credentials were retrieved through the application | The attacker **holds** a valid cloud credential, and that credential is **valid on** an identity. The chaining rules then conclude the attacker **owns** that identity. |
| **Exposed-secret validity** — a leaked secret was shown to be genuinely live | The same shape: the attacker **holds** a proven-valid credential that is **valid on** an identity, which chains to ownership of that identity. |
| **Google Cloud service-account impersonation** — a token was minted and shown to work as another service account | The attacker **holds** a minted token **valid on** the target service account, chaining to ownership of it. |
| **Cloud permission escalation** — the retained permission configuration permits an unconditional, genuine increase in privilege | Depending on the family of escalation: either a newly minted credential (the "holds" chain above), or a direct permission grant plus ownership over the escalated resource. |
| **Kubernetes anonymous privileged binding** — an unauthenticated subject is bound to full cluster administration | No credential is held at all. Merely *reaching* the cluster's control interface **is** administration. So the map mints the cluster control plane (a crown-jewel cloud resource) and the cluster secret store (a crown-jewel datastore), joined by "trusts for" arrows from the reached surface. |
| **Kubernetes dangerous-permission grant** — a dangerous action-and-resource permission is granted to a subject an attacker can occupy (the anonymous user, a default service account, or any authenticated user) | The same shape as the row above: reaching the interface *as that subject* is the grant, so the control plane and the secret store are minted and chained. |

Note the honesty in the last two rows. The system does not pretend a credential
was captured where none was. It models the *actual* achieved effect — which in the
Kubernetes cases is that no credential is needed at all. There is a committed test
asserting exactly this: that the anonymous case holds no credential, "that is
E1/E5, not E4".

### 6.5 The attacker is a pin on the map too

The map holds one pin representing the attacker. Everything the attacker has
achieved is recorded as arrows from that pin: what they **own**, what they
**hold**, what they have **reached**.

This has two useful consequences, and the code note says they are the point.

*Persistence.* The attacker's position is just part of the map, so it survives a
save and reload. An interrupted engagement resumes with exactly the foothold it
had.

*Chaining.* Because the attacker's position is expressed in the same vocabulary as
everything else, the reasoning rules operate on it directly. Holding a credential
that is valid on a target lets the system conclude that the attacker now owns the
target — which is precisely the chaining a flat list of findings cannot do.

---

## 7. Working out the chains

Recording what was observed is half the job. The other half is working out what
follows from it.

### 7.1 Inference rules

The system runs a small, strictly bounded reasoning engine over the map. A rule
says: *if these relationships all hold at once, then this further relationship
also holds.* Four rules are shipped as standard. They are kept in the code as two
pairs which the system joins into one working set — two rules about the estate
itself, and two about what the attacker has already achieved. It is worth naming the
split, because it is the seam where the picture of the organisation meets the picture
of the intruder:

| Rule | Which pair | In plain words |
|---|---|---|
| Transitive reachability | About the estate | If B can be reached from A, and C from B, then C can be reached from A. |
| Assume via valid credential | About the estate | If an identity can be reached from a foothold, and some credential is valid on that identity, then from the foothold that identity can be assumed. |
| Own via held credential | About the attacker | If the attacker holds a credential, and that credential is valid on a target, the attacker now owns the target. |
| Reach via owned host | About the attacker | If the attacker owns a machine, and a service is reachable from that machine, the attacker has reached that service. |

A derived relationship is written onto the map with a source label that marks it as
derived and names the exact rule that produced it — so it classifies as
*intelligence*, never as a proven fact, and any operator can see at a glance that
it was reasoned rather than observed. Its confidence is the product of the
confidences of the facts it was built from, which means a chain is never more
confident than its weakest link.

### 7.2 Techniques as machine-checkable moves

Alongside the general rules, the system holds a catalogue of **attack techniques**
expressed as machine-checkable moves. There are twelve: six in the core catalogue
(unauthenticated endpoint read, credential reuse, token replay, internal reach via
request forgery, role assumption, deserialisation to code execution) and six in an
extended catalogue (credential-leak capture, datastore secret extraction, host
takeover, lateral pivot, token-leak capture, session-theft takeover).

Each technique states, in the map's own vocabulary:

- its **preconditions** — what must already be true for the technique to apply;
- its **effects** — what becomes true if it fires;
- its **detection signals** — what a defender would see if it happened;
- which **automatic test** would confirm it.

The design note explains why this was built rather than adopted. Public technique
libraries such as ATT&CK and CAPEC describe techniques in prose. Prose cannot be
checked against a map. "Adversary uses valid accounts" has no machine-checkable
precondition and no machine-checkable effect, so a planner cannot decide whether
it applies here, or what becomes true if it fires. The note's summary: *"intel that
can't be executed is a library, not a plan."* Each technique in the catalogue does
carry its public reference — the ATT&CK, CAPEC or CWE identifier it corresponds to
— so the provenance of the idea is not lost.

The catalogue is explicitly **abstract, not armed**. It states what becomes
possible and how a defender would notice. It contains no attack payloads.

### 7.3 Three properties that make automatic reasoning safe

Letting software reason forward unattended is exactly where an over-eager tool
would start inventing things. Three properties prevent it here.

**It only ever adds.** Reasoning never removes a fact and never overwrites an
*observed* one. If a rule would conclude something already recorded from a real
observation, the conclusion is dropped and the observation's own provenance is
kept.

**It always stops.** The set of things that can be derived is finite, and a derived
confidence is a product of numbers no greater than one, so it can never exceed
what it was built from. There is a hard cap on the number of rounds on top of that.

**It always produces the same answer.** Rules are matched in sorted order and
stamped with a supplied counter, never a clock. The same map in, the same
conclusions out.

There is one further guard, on the reconnaissance side. The reasoning that runs
over collected intelligence — working out, for example, that an organisation
transitively owns a domain, or that two sites share infrastructure — is
**structurally incapable** of writing an attacker-movement arrow. Its writer
function refuses any arrow outside a two-item allow-list and raises an error
otherwise. Discovering that an organisation owns an address range can therefore
never be turned into a claim that an attacker can reach it.

### 7.4 The second pass, after the cloud picture arrives

There is a practical ordering problem the system has to solve, and it is worth
explaining because the fix is a good illustration of the discipline.

The chaining described above runs immediately after the web scan. At that moment
the map does not yet contain the cloud and identity facts, because those are folded
in afterwards, by a separate step — the system takes the operator's own exported
cloud configuration and other sensor outputs and re-runs the relevant automatic
tests over them. A route that only exists *because* of a cloud fact would therefore
be invisible: the first pass had already finished before the fact arrived.

So the system runs the route search a **second** time, after the cloud picture has
been folded in. The module's own note states the purpose exactly: the first pass
"runs BEFORE sensor fusion, so it never sees the cloud / IAM facts the fusion
oracles confirm. This module closes that gap." ("IAM" is short for
*identity and access management* — the part of a cloud account that decides who is
allowed to do what.)

The second pass is deliberately narrow, and the narrowness is the point.

**It bridges exactly two confirmations, and nothing else.** Only two kinds of
confirmed cloud fact are turned into arrows an attacker can walk along:

| Confirmed fact | The arrow it becomes | Why that is a faithful restatement |
|---|---|---|
| An unauthenticated request genuinely reached a cloud resource | The attacker **has reached** that resource | If anyone at all can reach it without logging in, then so can the outside attacker. This is a direct consequence of the test that fired. |
| An identity genuinely holds a permission path over a resource | That identity **has a grant** over that resource | A plain restatement of the permission the test confirmed. |

**It checks *which* test fired, not merely how strong the entry looks.** The code
requires the entry's source label to name the exact cloud test that produced it. It
deliberately does not accept "this entry is in the grounded tier" as sufficient,
and it deliberately does not accept a matching identifier prefix — the comment
notes that a web finding could carry a colliding identifier. Nothing else is
allowed to be restamped as a proven cloud fact.

**It never invents the attacker's foothold on an identity.** This is the safety
property that matters most. Confirming that an identity holds a powerful permission
does **not** produce a route. A route appears only if the attacker can already
reach that identity by some arrow another confirmed fact established — a stolen
credential that works on it, an owned machine with a live session, a
take-on-this-role relationship. A confirmed permission held by an identity the
attacker cannot occupy yields **no route at all**.

There is one small and deliberate exception, and it is worth stating because it
looks at first glance like an invention. If a confirmed permission names an
identity that is not yet a pin on the map, the pass adds that identity as a pin, so
that the confirmed permission arrow is not left hanging from nothing. That pin is
added at the *intelligence* tier, not as a proven fact, and it changes nothing about
reachability: an identity the attacker cannot get to is still an identity the
attacker cannot get to. The pin records what the confirmed permission said; it does
not grant anybody anything.

Two further safety details. If a confirmed finding turns out to point at more than
one thing — which can happen when two differently-typed cloud resources share a
name — the pass **skips it entirely** rather than guess which one was meant. The
code is explicit that this is the fail-safe choice: better to miss a route than to
wire a permission to the wrong resource. And re-running the pass over the same map
produces the same map: each arrow is identified by its two ends and its kind, so a
second run updates rather than duplicates.

**It is honest about the strength of what it surfaces.** The module states its own
limit in as many words. The arrows it writes are backed by confirmed tests, but a
surfaced route may also pass through the operator's *declared* cloud identity
structure — the organisation's own exported configuration, folded in as collected
intelligence. That is real ground truth about the customer's environment, not a
fabrication, but it is not itself independently proven by a test. So the honest
description of such a route is "grounded in the confirmed cloud facts plus the
operator's own declared structure", which is weaker than "every single step
independently proven". The code says plainly: *"We never assert the latter."*

Three operational notes.

**It only runs when there is a cloud picture to fold in.** The folding step turns
itself on when the operator has actually written the file listing which exported
configurations to read, and the operator can also switch it on or off explicitly;
an explicit "off" always wins. With no such file and no explicit request, the
folding step does not run, the second route search does not run, and the engagement
behaves exactly as it did before — byte for byte identically. Nothing about this is
enabled quietly.

**It can also run entirely on its own.** There is a mode that performs no web scan
at all: no starting address, no crawling, no probing — only the folding of the
operator's own exported cloud configuration and the route search over the result.
That is the natural mode for an organisation that wants its cloud posture reviewed
without anybody touching its website. If the file is missing, empty or malformed,
the run returns an honest empty result — zero suspicions, zero facts — rather than
inventing anything.

**A failure here never damages the engagement.** The second pass is wrapped so that
if it fails for any reason, the engagement continues and the findings and verdicts
are untouched. It can add routes; it can never remove or alter a finding.

One point of honesty to carry forward. The mechanism described in this section is
built and tested. What it can actually *surface* on a live customer estate depends
on the cloud and Kubernetes confirmations that feed it, and their live-fire status
is stated plainly in section 17: three of the six have been fired at something real
— the two Kubernetes ones against a real cluster the system stands up, owns and
destroys itself, which is the project's own infrastructure rather than a third
party's, and the GitHub half of the exposed-secret check against the real GitHub
service, the only one of the six to have judged material from a real outside system
— while the rest, including that check's Amazon Web Services half, are proven against
recorded sample data standing in for a real cloud account, with pointing them at a
live third-party cloud account still waiting on the customer supplying their own
credentials.

---

## 8. "Crown jewels": the things that actually matter

An attack route is only interesting if it ends somewhere that matters. The system
calls those destinations **crown jewels** — a plain borrowing of the ordinary
phrase.

### 8.1 What counts as a crown jewel

By default, crown jewels are the **datastores** (databases, storage buckets,
secret stores) and the **cloud resources** on the map. The scan-driven analysis
also includes **hosts**. The operator can override the list.

The system then asks the archetypal question: standing at this foothold, which of
these can I reach, and by what explainable route? It deliberately reports the
crown jewels it *cannot* reach as well as those it can, so the answer is a
complete picture rather than a highlight reel.

### 8.2 Telling the system what a thing is worth

Structure is not worth. Two databases are not interchangeable if one holds test
data and the other holds citizen records. Left alone, the system would treat every
crown jewel as worth the same.

So an engagement may supply a small file stating relative worth, placed alongside
the engagement's other paperwork.[^3] It supports three levels of specificity: a
value for a **named individual thing** (highest priority), a value for a **whole
category**, and a **default** for everything else. The values are on any positive
scale the customer finds natural; only the ratios matter, and the numbers are never
treated as money.

Two properties of this deserve emphasis for a procurement reader.

It is **optional**. With no such file, the system falls back to treating every
crown jewel as worth 1.0 — and says so, in the report, in a line stating that a
uniform model was used because no worth file was supplied. The rankings then become
an honest *count* of attack routes rather than a weighting of value. Nothing is
silently assumed.

It is **fail-safe**. If the file is missing, malformed, or unreadable, the system
degrades to the uniform model rather than failing or guessing.

---

## 9. Ranking the routes

### 9.1 What a route is

A route is an ordered chain of arrows from a starting point to a crown jewel, with
no thing visited twice. In report form it reads like a line of stepping stones:

> attacker → the vulnerable web interface → the cluster control plane → the
> cluster secret store

Each hop is labelled with the technique or the finding that established it.

### 9.2 How routes are ordered — most credible first

The naive approach is to enumerate every possible route. The system can do that,
and caps it at six hops by default — but the design note is candid that exhaustive
enumeration "drowns the operator in routes and has no notion of which one an
attacker would actually take".

So the ranking used in practice asks a better question: *which route would an
attacker actually take?* Each arrow is given a cost derived from how strongly it is
believed — the less credible the step, the more it costs. Standard, well-understood
route-finding then produces the *cheapest* route, which by construction is the
**most credible** route. A second standard algorithm extends this to the best
handful of routes rather than only the single best.

An arrow believed at zero is treated as infinitely expensive: unusable.

### 9.3 The cautious ranking

There is an optional **risk-averse** mode. Instead of ranking by the headline
confidence, it ranks by the conservative lower bound described in section 3.2.

The practical effect: a step that *looks* strong but has been seen only once ranks
*below* a slightly weaker step that has been corroborated repeatedly. The planner
prefers routes it has actually corroborated. For a government reader this is the
difference between "the model says this is the likeliest path" and "this is the
path we have the most evidence for" — and the system can be asked for either.

### 9.4 Every route reports its own weakest link and its own paper trail

Every route carries two things that make it auditable rather than merely asserted:

- **The weakest-link confidence.** A route is reported as no stronger than its
  least certain hop. There is no averaging that could let two strong steps disguise
  one shaky one.
- **The chain of sources.** The exact source label for every hop, in order. An
  operator, an auditor, or an oversight body can walk a route backwards and ask,
  hop by hop, "what made you believe this?" — and get a specific answer each time.

The design note states the intent plainly: this "is what turns an attack path from
an oracle's assertion into something the operator can audit".

### 9.5 Loudness: choosing a quiet route

Each route also carries a **detection cost** between 0 and 1 — an estimate of how
noticeable it would be to a defender.

It is built from two separate inputs: how many independent observable tells the
technique has (written into the technique catalogue by the operator), and how
loudly those tells would register in a defender's monitoring. A route is as loud as
the combination of the ways its steps could be seen.

Two points of honesty in the code deserve repeating here. First, this is
*defensive awareness*, not evasion: the module states that knowing a technique
would trip a firewall rule is awareness, "not an evasion recipe", and that the
framework stays correlatable — meaning the customer can always find this system's
own traffic in their own logs. Second, when the system is asked for the most
valuable set of routes that fits within a stated noise allowance, it works the
answer out **exactly** rather than approximately.

That second point is worth one more sentence, because it is a small piece of
engineering honesty that runs against the usual direction of travel. The question
is the familiar one of packing a bag: each route has a value and a loudness, there
is a limit on total loudness, and the task is to choose the most valuable
combination that stays under the limit. Software often answers this kind of
question with an educated guess that is usually good and occasionally wrong. This
system used to do exactly that. It now computes the provably best answer instead,
because the number of candidate routes is small — the search returns at most eight
— and at that size the exact method is both simpler and strictly better. The code
comment records the replacement in plain terms: the exact solver "is both simpler
and strictly stronger than the simulated-annealing heuristic this used to run".

---

## 10. Blast radius: what a foothold actually exposes

Before routes and repairs, the system answers a simpler and often more arresting
question: *from this one starting point, how much of the organisation is in reach?*

The report states it directly. It names how many crown jewels are reachable out of
how many exist, how many things in total are in reach, and — if a worth file was
supplied — how much business value that represents out of the total.

Written out in words, the line the report produces says something like this:

> An attacker standing at the machine named as the starting point reaches **3 of the
> 7** crown jewels. **41** things on the map in total are within their reach. That
> represents **62.0 out of 118.0** of the total business worth on the map.

Three notes on how to read that.

- The starting point is named by the operator, using the same label that thing
  carries on the map — for example the machine that a confirmed weakness gave the
  attacker a foothold on.
- "41 things on the map" counts every pin the attacker can get to, not only the
  valuable ones: the machines, the pages, the accounts and the network zones along
  the way as well as the destinations.
- **The worth figures are relative, not monetary.** As section 8.2 explains, the
  numbers come from a small file the customer writes stating what each thing is
  worth relative to the others. "62.0 out of 118.0" therefore means *just over half
  of everything the customer said they cared about*. It is not pounds, dollars or
  euros, and the system never claims it is. With no such file supplied, every crown
  jewel counts as 1.0 and the same sentence becomes an honest count of destinations
  rather than a weighting of value.

That single sentence is the translation from a technical issue list into a
board-level statement of exposure. It is also, importantly, *bounded*: it is a
statement about what is reachable given what has been observed and proven — not a
claim to have enumerated every possible thing in the estate.

---

## 11. Chokepoints: which single fix breaks the most attacks

Knowing that thirty routes exist is interesting. Knowing that fixing *one* thing
eliminates twenty-two of them is actionable. This is the output the system is built
to produce, and it is the part most directly useful to a remediation programme with
a finite budget.

### 11.1 How a chokepoint is found

For each crown jewel that is reachable, the system enumerates the short routes to
it and counts how many of them pass through each individual connection. That count
is a measure of how *busy* a connection is: the road junction most of the traffic
happens to use.

A busy junction is not enough on its own, though — traffic may simply divert around
it if it closes. So the system then does something exact: for every connection appearing
on any route, it removes that one connection and re-checks reachability. If a crown
jewel becomes unreachable, that connection is a genuine single point of failure for
the attacker's route — the code calls it a **bridge**.

The distinction matters in practice, and the code states it directly: cutting a
bridge is a guaranteed win, and where no single cut disconnects anything, the best
one thing to fix is whichever connection the largest number of routes run
through.

### 11.2 Ranking by value, not by count

The chokepoints are then re-ordered by the **worth** of what each one severs, not
merely by how many things it severs. Where two come out equal, the tie is broken
first by whether the connection is a genuine single point of failure, then by how
many routes run through it, and finally by a fixed label, so that the same map always
produces the same order.

The intended reading is exactly the one a programme manager wants: *fix the one
connection that severs access to the payments store first.*

### 11.3 The "what if we fixed it" calculation

Finally, the system runs a "what if" calculation on the top chokepoint: if this one
connection were repaired, which crown jewels become unreachable, which remain
reachable, and how much exposure is removed?

Written out in words, the output says something like this:

> Cutting the number-one chokepoint — the arrow saying *this thing trusts that
> thing for some purpose*, running from the first named thing to the second — cuts
> off **2** crown jewels and removes **45.0** of the worth on the map. **17.0**
> would still be reachable afterwards.

The report names the two things at each end of that arrow, and the kind of
relationship the arrow records, so the engineering team knows exactly which
relationship to sever. Once again the worth figures are relative rather than
monetary: 45.0 removed against 17.0 remaining means this one repair takes away
roughly three-quarters of the exposure from this foothold.

Two engineering properties make this trustworthy. It is a **pure calculation** — it
never modifies the map and never sends any traffic. And it reports what would
*remain*, not only what would be fixed. Reporting the residual exposure in the same
breath as the win is what makes the number usable for planning rather than for
reassurance.

---

## 12. Keeping the map honest

A map that accumulates claims and never re-checks them becomes a liability. Over
weeks, an entry recorded when a weakness was real stays on the map after the
weakness is fixed, and every route built on it becomes fiction. The system has
several distinct mechanisms to prevent this.

### 12.1 A claim that no longer re-proves grants the attacker nothing

This is the central one.

When the system rebuilds a map from a **stored** report — for example, when an
operator opens a saved engagement in the console and looks at the attack graph — it
does not take the stored "confirmed" marking at its word. For each finding, it
**re-runs the original automatic test over the retained evidence, then and there**.

- If the test **produces the same result again**, the finding is written onto the
  map with a source label naming the test that fired — the *grounded* tier, and the
  only tier the rest of the system will accept as fact strength.
- If the test **does not produce the same result**, the finding is still recorded —
  it is not hidden — but with a downgraded source label marking it as withdrawn,
  which classifies as *ungrounded*, plus an explicit marker saying so. Its
  annotation arrow is downgraded the same way.

And crucially, **the derived consequences are withheld entirely**. The reach the
finding would have granted, the pieces of network structure it would have added to
the map, and the routes those would have fed are all skipped. The code comment
states the outcome in one line: a recorded-confirmed finding whose proof no longer
reproduces "grants the attacker NOTHING".

There is a committed test asserting exactly this for the Kubernetes case: a finding
whose proof does not re-fire produces no cluster pin and no secret-store pin at all.

The behaviour is also **fail-closed**: if the finding cannot be graded for any
reason — an error, missing evidence — it is treated as *not* a fact. The system
defaults to withholding, not to granting.

An ordinary-life comparison: this is a laboratory that will not accept last month's
result printed on a slip of paper. It re-runs the same test on the sample it kept
before it lets the result inform any decision. If the test does not come out the
same, the result stays in the file marked "did not reproduce" — and nothing further
down the line is allowed to act on it.

### 12.2 A withdrawal must itself be proven

The mirror-image rule, from section 5, bears restating in this context: a record
that *retracts* a claim only lowers belief if the retraction is itself backed by
signed evidence. An unauthenticated retraction of a proven fact is ignored.

Together these two rules close the loop from both directions. An unproven claim
cannot become a fact. An unproven opinion cannot un-prove a fact. Only evidence
moves the needle, either way.

### 12.3 The map can authorise nothing

The map is a lens, never a source of authority. This is enforced structurally
rather than by policy.

The session-scoped graph store, which materialises the per-job view described in
section 15, has **no method** to promote a finding, grant a permission, raise a
privilege level, or authorise an action. The documentation explains the reasoning:
*"a projection that could feed a decision would be a covert channel around the
oracle."*

The same holds for the cross-job retrieval described in section 15.4: results are
returned in a structure that is permanently marked non-authoritative and is
*frozen*, so a consumer cannot flip the flag and fabricate a grant. Any action those
results suggest still has to clear every gate the system has, exactly as if the
suggestion had never been made.

### 12.4 A separate rule for claims that lean on the map

The system has a component whose job is to check claims by re-executing whatever
they cite — the software calls it the *veracity firewall*. When a claim cites *the
map* as its ground, that component applies three tests at once: the cited thing
must be one the claim actually names; its conservative belief lower bound must be
at least 0.5; and its grounding tier must be *grounded*. Collected intelligence and
derived conclusions are legitimate information — but they cannot reach fact
strength.

**An honest note on this component, which must not be softened.** It is genuinely
in live use. It is called at real points in the running system, not only from its
own tests: when a report is rendered, so that every finding is re-graded before it
is printed; when a finding is written onto this map, so that a proof which no
longer reproduces cannot be recorded as proven; on each finding at the end of an
engagement; by the reviewing components that look for findings claiming a proof
they can no longer produce; and by the defensive gateway before it will issue a
certificate.

What it is **not**, today, is a single universal checkpoint that every claim in the
system crosses. The distinction matters and is worth drawing precisely.

- **Findings** written onto this map *are* put through it — that is the
  re-execution described in section 12.1, and it is the path that matters most for
  this chapter.
- **Every other write to the map** — a machine discovered, a network zone observed,
  a relationship reasoned out — is *not* routed through it. Those writes are
  classified by the shared grounding rule described in section 3.1. That rule is the
  very same code the claim-checking component itself calls, so the two can never
  disagree about what counts as proven; but classifying a write and re-executing a
  proof are different operations, and this briefing does not conflate them.

One further note, for accuracy rather than for comfort. The written note inside
that component's own source file still describes it as a building block "exercised
only by its tests", which the code around it now contradicts — the live call sites
listed above were verified directly for this briefing. Earlier drafts of these
chapters repeated that note. The correct position is the one stated here: the
component is in live use at named points, and it is not a universal gate. The
direction of the stale note was to *understate* what is built, but a document whose
value rests on its facts being re-derived should not repeat a stale description of
its own software, and the note should be corrected at source.

### 12.5 Inference cannot invent access

Restated from section 7.3 because it belongs on the honesty list: the reconnaissance
reasoning is structurally prevented from writing attacker-movement arrows. It can
conclude that an organisation owns an asset. It can never conclude that an attacker
can reach one.

---

## 13. What the operator actually sees

### 13.1 The Attack Graph screen

Within the Findings area of the console there is an **Attack Graph** tab. It shows
four summary tiles — how many things, how many connections, how many
attacker-to-crown-jewel routes, how many chokepoints — over a drawn diagram of the
map, with the different kinds of things colour-coded.

Alongside it sit two panels. **Attack paths** lists each route with its hop count,
its detection cost and its value. **Choke-points** is a table with columns for the
connection, its kind, how many routes it severs, how much value that cuts, and
whether it is a genuine bridge.

Clicking any pin opens a detail panel showing its type, its belief, its confidence,
its **grounding tier**, where it came from, and the list of every arrow touching it
— each marked FACT or LEAD. If the pin's grounding is anything other than proven,
the panel says so explicitly, in a plain sentence. The screen's exact words are:
*"This node's grounding is 'X' — it is inferred/unproven, not an oracle-confirmed
fact."* ("Node" is the screen's word for what this chapter calls a pin; "oracle" is
its word for an automatic test.)

The empty states are honest too. When no route exists, the panel does not go blank
or imply safety: it says "No attacker→crown-jewel path — nothing chains to a
modelled crown jewel." When no single connection severs a route, it says so rather
than inventing a recommendation.

### 13.2 The Timeline replay

A **Timeline** tab lets the operator drag a slider and replay how the map grew, in
the order the reasoning discovered it. A counter beside the slider reports where
the replay has got to — for example: step 7 of 21, showing everything recorded up
to counter value 34, at which point the map held 18 pins, 22 arrows and 3 complete
routes. (The screen writes those last three as "nodes", "edges" and "paths".)

One detail is worth calling out as characteristic of the system's temperament. At
any point on the slider, routes and chokepoints are shown **only if every step of
them exists at that point**. The code comment says why: *"honest — no premature path
highlight."* The replay will not flatter the analysis by drawing a conclusion before
the evidence for it arrived.

The whole replay is a reconstruction from the record. It sends no traffic.

### 13.3 The Fixes screen

A separate **Fixes** screen presents the same chokepoint analysis under the heading
**Highest-impact fix points**, listing the connection, how many routes it severs,
and whether it is a bridge — next to the list of confirmed, fixable findings. The
screen states in plain text that only findings an automatic test confirmed are
eligible, and that unproven suspicions are never automatically fixed.

### 13.4 The command-line triage report

The same analysis is available with no interface at all, as a single typed command.
The operator names the engagement, points at the signed record, and names the
starting point; the system does the rest.[^4]

It writes two files: one written for a person to read, and one written for other
software to read. The document written for a person has the structure a defender
acts on:

1. the foothold, the crown-jewel categories, which connections are treated as
   walkable, whether a worth file was used, and which ranking was applied;
2. the blast radius;
3. the shortest and most credible routes;
4. the chokepoint ranking — "the single most valuable remediation first";
5. the counterfactual on the top chokepoint.

Two properties make it suitable as a formal deliverable. It is **read-only and sends
no traffic** — it reasons over the already-collected record. And it is
**deterministic**: the same record produces byte-identical output, so the report is
a reproducible artefact rather than a one-off rendering. A recipient can regenerate
it and compare.

If the named starting point is not on the map, the report says so with a visible
warning rather than silently producing an empty analysis.

---

## 14. Five different pictures, named honestly

The word "graph" appears in more than one place in this system, and it would be easy
to conflate them. They are distinct components with different sources and different
jobs.[^5]

Four of them are views of the same work: one engagement, against a target the owner
has been authorised to test. Those four are set out immediately below. The fifth is
not a view of that work at all — it sits on the sovereign side of the wall, its
subject is the owner rather than a target, and it is described at the end of this
section. **Merging the fifth with the other four is the most misleading mistake a
reader of this chapter could make**, which is why it is named here rather than left
to be met four chapters later.

| | What it is | What it answers |
|---|---|---|
| **The world model** | The asset map described in this chapter: things, connections, beliefs, routes, chokepoints. | *What is reachable, and how much would it cost us?* |
| **The attack-chain view** | A record of how the engagement unfolded: chains, steps, findings, failures, decisions, bridged to the reconnaissance picture. Every finding pin is either CONFIRMED or LEAD — distinct states, so a query for facts cannot return a suspicion. Retirement is done by marking, never by deletion, so history survives. | *How did this engagement actually proceed?* |
| **The session partition** | A per-job view of the signed record itself: one pin per event, one per acting component, arrows for which event caused which and which entry replaced which. Purely derived, disposable, rebuildable. | *What happened in this job, laid out visually?* |
| **The reasoning-chain structure** | A structured, reversible view of the *conversation* behind the work — the sequence of instructions, questions and tool results the reasoning components exchanged. | *What was said, in what order, on the way to this conclusion?* |

The first three obey the same discipline: one-way projection from the signed record,
no clock, no randomness, reproducible byte-for-byte, and no ability to authorise
anything.

The fourth deserves a short explanation, because it addresses a problem that is
easy to overlook. A long engagement produces a very long conversation, and at some
point that conversation must be shortened or it becomes unmanageable. Shortening a
record is exactly the kind of operation that quietly destroys an audit trail. So
this component shortens it in a way that cannot lose anything:

- **Nothing is ever deleted.** A summary is *added* as a new entry. The originals
  stay where they are.
- **Every summary states precisely what it covers.** It cites the exact range of
  original entries it stands for, by their position in the record, in a form that
  can be checked mathematically. A reader can always go back to the originals a
  summary claims to represent and confirm that it covers what it says it covers.
- **Summaries are labelled as summaries, never as facts.** The code is explicit:
  every summary entry is tagged as such, and *"nothing here makes anything true or
  authorizes anything."*
- **The structure can be taken apart and put back together unchanged.** Reading the
  record into this structure and writing it back out again produces byte-identical
  output, because the operation only groups the material — it never rewrites it.

The component that writes the summaries is an artificial-intelligence component,
and the design treats it accordingly: it is supplied from outside, it has no
authority, and its output is marked as a summary rather than as evidence.

**One honest deployment note.** The per-job partition can be kept in either of two
places. The default is a store built into the system itself, which writes ordinary
files on the operator's own machine and needs nothing else installed. There is also
an optional second choice: a separate, specialised database (a product called
Neo4j) running elsewhere, written to work through exactly the same interface so
that nothing else in the system has to know which one is in use.

In the environment examined for this briefing, that second choice is not available:
neither the small piece of software needed to talk to that database nor a running
copy of the database itself is installed. Two things follow, and both are the
correct behaviour rather than a workaround. Asked to use it directly, the system
stops with a clear error message and the test covering it is recorded as skipped in
plain view, not passed quietly. And when the system tries to *copy* its work into
that database as an optional extra, it checks first: if no connection details have
been given, or the machine cannot be reached, it simply proceeds without copying.
The code's own phrase for this is that it "never fakes a connection".

**The built-in store is the default and requires no external database.** Nothing in
this chapter depends on the external one.

**The fifth picture, and the one that must never be merged with the others.**
Everything above is a view of an engagement. There is one more graph in this system,
and it is not a view of an engagement at all. It belongs to the sovereign side — the
half of the system that runs the owner's own affairs and performs no offensive work —
and it is that half's memory.[^6]

Its subject is the owner. It holds the projects the owner works in, the working
sessions they have had, the documents they have kept, and the code commits they have
made, together with which project each of those belongs to. That is the whole of it.
**Nothing on it is a machine, an address, a credential, a defensive control, a
weakness or an attacker.** It has no routes, no chokepoints, no blast radius and no
crown jewels, because it is not a map of anywhere an intruder could stand. The traffic
does not run the other way either: nothing about the owner's own working history
appears on the attack map this chapter describes.

| | The attack map — this chapter | The owner's record — chapter 14 |
|---|---|---|
| **Whose estate it describes** | Someone else's, under a signed charter | The owner's own |
| **What it is built from** | The signed record of one engagement | The sovereign side's own signed journal |
| **What is on it** | Machines, services, identities, credentials, defensive controls, confirmed weaknesses | Projects, working sessions, documents, code commits |
| **What a connection means** | Reachability and trust — who can get to what | Containment — which project a thing belongs to |
| **How sure it is** | Every entry carries one of the four grounding labels of section 3.1, and a belief that can fall | Every entry is derived mechanically; there is no belief number on it at all |
| **The question it answers** | *What is reachable, and what would it cost us?* | *What has the owner already done, and where is it written down?* |
| **Where it runs** | Inside the offensive engine | Inside the sovereign side — a different process, a different place on disk |

**The difference in the trust rules is sharper than the difference in the contents.**
The attack map is deliberately permissive about what it will hold. It admits entries
at all four grounding labels of section 3.1, including entries an
artificial-intelligence component merely suggested, and its honesty comes from
labelling them and from refusing to let a poorly grounded entry carry weight it has
not earned.

The owner's record works the other way round. Its structural layer admits only what
can be derived mechanically from the signed journal: read the journal in order, count
what is there, write down what was counted. There is no extraction step and no
judgement — and so there is nothing for a belief number to measure. Richer entries
have been designed and are deliberately left out: people, organisations, decisions,
commitments, and the relation of one record contradicting another are, in the code's
own words, *"intentionally absent until a grounded producer exists for them"* — that
is, until something exists that can produce them with a proof attached. A briefing
usually has to explain why a component is thinner than its design document. Here the
thinness *is* the design, and the missing rows are a refusal rather than a backlog.

**What the two share is discipline, and it is the same discipline.** Both are one-way
projections from a signed record. Neither is a source of truth. Both can be discarded
and rebuilt from the record they came from. Both make every entry cite the exact
record entry that produced it — by position and by fingerprint — so any answer can be
walked back to tamper-evident memory. On the owner's side there is one honest
exception, set out in full in chapter 14: the project entry is a tally over the things
inside it rather than something any single record minted, so it carries no citation of
its own and is walked back through the sessions, documents and commits it contains.
Both refuse to fabricate: asked about a name it
does not hold, the owner's record replies that it has no entry matching that name,
rather than composing one. And neither can authorise anything. The owner's record is
opened for reading only; a statement that would write to it is refused twice over,
once by an explicit check on the request and once because the connection itself was
opened read-only; and no gate, no approval and no permission decision anywhere in the
system consults it.

**They never meet.** The two halves run as separate operating-system processes out of
separate installed environments, and the offensive engine is simply not present in the
personal one — which is why the separation does not rest on anyone remembering to
enforce it. On top of that absence sits a guard, and chapter 14 gives its honest
measure: as each of the personal side's main subsystems loads, it scans what is already
in memory and refuses to continue if anything offensive is there — in the words of the
error it raises, a "sovereignty violation". Two limits belong with it. The guard is
fitted to those main subsystems one by one rather than to the personal side as a whole,
and the memory graph this section describes is not one of the places it is fitted. And
it looks at what is loaded at that moment, so it catches offensive code already present
rather than code arriving later. The guard is the smoke alarm; the wall is the absence
and the process boundary. There is therefore no path by which the attack map could read
the owner's private history, and none by which the owner's history could acquire a
target's.

**Honest status.** The owner's record graph is live on the machine examined for this
briefing: a built copy exists, derived from the sovereign journal, and it records how
far through that journal it had read, so a reader can tell whether it is current or
has fallen behind. Its derivation step is covered by a test that replays the same
journal twice and requires the two results to be identical. Rebuilding it is a command
the owner runs, not a background service: it refreshes when asked, and the interface
reports the gap between the picture and the journal rather than hiding it. Chapter 14
gives the full account of that side — what it is made of, what the nightly
consolidation pass does with it, and what it is allowed to say. This section exists
only so that a reader of *this* chapter never merges the two.

---

## 15. Per-job maps, and memory across jobs

### 15.1 Sessions

A **session** is a named, durable container for one line of work — the runs and the
conversation belonging to a single job. The operator can create, rename, reopen and
delete them. Sessions are stored on the operator's own machine, in a folder
readable only by that user. Each write is done in one indivisible step — the new
version is prepared in full and then swapped into place — so a crash can never
leave a half-written record behind.

Ordering within the registry uses a counter, not a clock, for the same
reproducibility reason as the map. A separate clock timestamp exists purely to sort
the list in the interface.

The registry has no authority. Creating, renaming or deleting a session changes no
finding and no gate.

### 15.2 Each session owns its own partition of the map

Every session owns its own **partition** — its own private slice of the derived
view — keyed by the session's identifier. Partitions are isolated: projecting one
never touches another.

The partition is rebuilt from the session's slice of the signed record, and only
from that. Because the rebuild is a pure function of those events with no clock and
no randomness, the same record always yields an identical partition.

Deletion is deliberately fail-safe, and comes in two strengths. A **soft** delete
leaves a marker and retains the conversation, the run records, and — always — the
signed record. A **hard** delete additionally removes the registry entry and drops
the partition, "but never touches the spine or a FACT". Because the partition is
derived, dropping it loses nothing: it can be rebuilt from the record at any time.

### 15.3 Connecting one job to another

An operator can **connect** session A to session B, so that work in A may draw on
what B learned. Four properties are worth stating for an oversight reader:

- **It requires an explicit act.** The operator's action *is* the consent. There is
  no automatic sharing.
- **It is one-directional.** A reading B does not let B read A.
- **Nothing is copied.** The connection stores only B's identifier in A's record. It
  is a read-time scope, not a merge. Disconnecting therefore re-isolates A
  immediately, with no residue.
- **It is bounded.** A session may not connect to itself, and there is a hard cap on
  how many connections it may hold.

A session also exposes its **open threads** — the runs that have not reached a
finished state, so a successor knows where to pick up. This is explicitly marked
advisory: it mints nothing and reads no authority.

### 15.4 Memory across engagements

Separately from the per-job view, the system keeps a persistent **memory store**
across engagements — a local database recording past engagements, findings,
hypotheses, test inputs, and dead ends. (A *test input* — the software calls it a
*payload* — is the specific thing the system deliberately sends to a target to see
how it reacts.)

Its purpose is to start a new job warm rather than cold: what worked against a
similar target before, which lines of enquiry paid off, which were dead ends worth
not repeating. For each combination of target type, weakness class and surface
pattern, it keeps a simple running tally of attempts and successes, and derives a
smoothed success rate plus a conservative statistical lower bound for cautious use.

Two disciplines apply.

**Past experience is recorded, never invented.** These stored expectations — the
software calls them *priors* — are written after the fact, from real engagement
outcomes. None is guessed at or generated.

**Every recall says where it came from.** Each result names the engagement and the
record it came from. The memory documentation states the standard bluntly:
*"Hallucinated priors are a fatal bug."*

### 15.5 What memory is never allowed to do

Cross-job retrieval returns a structure that is permanently and immutably marked
**non-authoritative** and **retrieval-only**. Confirmed findings and unproven leads
are returned in *separate* lists, so a lead is structurally unable to appear where a
fact is expected. Only currently-valid entries are returned; a retired lead is
excluded.

And nothing retrieved grants anything. The module states it directly: having
appeared in an earlier chain of work authorises nothing. Any action the retrieved
material suggests must still clear every safety check in turn — the component that
decides how dangerous an action is, the approval step where a human says yes, and
the gate that controls whether anything may be sent out to the target at all —
exactly as it would have done had the suggestion never been made.

---

## 16. The software supply chain on the same map

The map also carries the software supply chain, using the **package** pin type and
the **depends on** arrow.

An operator can supply a software bill of materials — a machine-readable inventory
of the components an application is built from — and the system projects it onto
the same map: one pin per component, one arrow per dependency. Two standard file
shapes are accepted, and a malformed entry is skipped rather than allowed to break
the ingest. This is done **offline, from a file the operator exports**; the system
does not go out and scrape package registries, which is consistent with its rule
that outbound traffic is gated.

Published advisories attach to those components with the **affects** arrow. The
comment in the model is careful about status: an advisory naming a package is a
**lead from threat intelligence**. What turns it into something stronger is a
separate deterministic test that proves a specific installed version genuinely falls
inside the advisory's stated affected range.

That distinction is the difference between "a scanner told us this component is
mentioned in an advisory" and "we can demonstrate that the version you are actually
running is inside the affected range".

The wider build-and-release safeguards — locking every software component the system
itself installs to an exact version *and* to a fingerprint of the exact file, pinning
the container base images it is built on to one exact verified version rather than
"whatever is newest today", producing the bill of materials as part of the build, and
a release gate that blocks a proposed change outright if a critical vulnerability is
found — belong to the system's own delivery pipeline, and they have their own
chapter.

Their status is stated here rather than left to be looked up elsewhere, because a
claim and its boundary belong in the same place: this work was completed and folded
into the released main line of the software on the day this chapter was written. The
chapter on evidence and proof gives the detail and the exact scope. It is mentioned
here at all only because the bill of materials that pipeline produces is one of the
inputs this map can consume.

---

## 17. What is fully working, what is built but not yet fired at a live third party

This section exists because the honesty of these distinctions is the product's
central claim, and a national agency reader must never be misled about them.

**Fully working, end to end, exercised for real:**

- The map itself — the pins, the arrows, the record of where each entry came from,
  the two belief measures, the merge behaviour, the clock-free reproducibility.
- Building the map from the signed record, including the "confirmed means signed"
  rule and the "an opinion cannot un-prove a proof" rule.
- The reasoning rules and the twelve technique moves.
- Route finding: exhaustive enumeration, best-route ranking, the cautious ranking,
  weakest-link reporting, source chains, loudness accounting, and the exact
  selection of the most valuable set of routes that fits a noise allowance.
- **The second, post-cloud route search** described in section 7.4. The whole
  mechanism is built, wired into both the routes that use it, and covered by tests:
  the bridging of the two confirmed cloud facts into walkable arrows; the refusal to
  bridge anything that was not confirmed by one of those two named tests; the refusal
  to invent the attacker's foothold on an identity; the skipping of any confirmed
  finding that points ambiguously at more than one thing; and the re-running of the
  same route search over the enlarged map. It runs in two places — after a web scan
  once the cloud picture has been folded in, and in the posture-only mode that folds
  in the cloud picture with no web scan at all. It is switched on by the operator
  supplying the file that lists which exported configurations to read (or by asking
  for it explicitly), and an explicit "off" always wins; with neither, it does not run
  and the engagement is byte-for-byte what it was before. A failure inside it can
  never alter a finding or a verdict. What it can actually *surface* on a live
  customer estate depends on the cloud and Kubernetes confirmations listed below,
  whose own live-fire status — proven for Kubernetes and for the GitHub half of the
  exposed-secret check, still pending for the rest of the cloud work — is stated
  there.
- Crown jewels, the optional worth file and its safe fallback, blast radius,
  chokepoint detection including exact single-point-of-failure detection,
  value-weighted ranking, and the counterfactual.
- The re-execution safeguard: a stored finding whose proof no longer reproduces
  grants no reach, no added network structure and no route.
- The interface screens (attack graph, timeline replay, fixes) and the command-line
  triage report with its reproducible output.
- Sessions, per-session partitions, connections between sessions, the
  cross-engagement memory store, and the append-only shortening of the
  reasoning-chain record described in section 14.

**Three of the six fired at something real — one at an outside system, two at the
project's own infrastructure; live fire against a
third-party cloud account still pending for the rest, by design.** The six cloud and Kubernetes confirmations
described in section 6.4 — metadata credential capture, exposed-secret validity,
Google Cloud service-account impersonation, cloud permission escalation, and both
tiers of Kubernetes permission checking — are wired end to end. For each of them the
detection logic, the evidence handling, the certificate issuing, the safety gates and
**the projection onto this map** are complete and proven.

For the **two Kubernetes** confirmations that proof now runs against a real
Kubernetes cluster: a repository script stands up a genuine single-node cluster (k3s
1.31.5, in a container on the machine's own internal address) which the system
creates, owns and destroys, plants known-dangerous and known-benign access rules in
it, and adjudicates what the real Kubernetes interface returns through the production
path. The dangerous binding is confirmed and its certificate re-verifies offline; the
benign ones, including the namespace default identity bound to the built-in `admin`
role whose real rules do grant secret reads, correctly stay leads. What that run does
not cover is a scope-gated *enumeration* capability discovering bindings across a
cluster, and a managed provider's control plane (Amazon EKS, Google GKE, Azure AKS).

A third has since joined them, and it splits inside itself. **Exposed-secret
validity** recognises two kinds of leaked credential. Its **GitHub half is proven
against the real GitHub service** — a second repository script drives the real,
permission-gated component over a real network connection, using the operator's own
credential against GitHub's own least-privileged identity endpoint; the credential is
confirmed, the certificate re-verifies offline, and a bogus credential of the same
shape sent live to the same real address is rejected by GitHub itself and correctly
stays a lead. Its **Amazon Web Services half is not proven at all**: built,
unit-tested, never exercised against real Amazon infrastructure, still needing an
access key only the account owner can issue, and **nothing from the GitHub run
transfers to it.**

For the **remaining cloud** confirmations — metadata credential capture, Google
Cloud service-account impersonation, cloud permission escalation, and that Amazon
half — the proof is offline, against recorded sample
data standing in for the real thing — evidence files written to the exact shape a
real cloud account produces, and, to say it once more plainly, written for the
purpose rather than harvested from anybody's live cloud account.

What remains outstanding is a single, specific, operational thing: **pointing those
cloud confirmations at a live third-party cloud account.** That waits on the customer
supplying their own credentials. The system's own machine-readable capability
registry records no engineering work outstanding against them; the remaining deferral
is operational, not
technical.

One of the six is different and must be described differently. The **cloud
permission escalation** capability works by re-deriving the answer from the
customer's own retained permission configuration, offline. Running the escalation
for real against a live account is **deliberately not part of it**, on the stated
principle that a defensive verification tool does not execute the escalation it is
warning about. That is a permanent design position, not a pending item.

**Built, but dependent on equipment that is not present here.** The optional
external graph database is a real, reviewable piece of work, but in the environment
examined for this briefing neither the small piece of software needed to talk to
that database nor a running copy of the database itself is installed. Asked to use
it, the system stops with a clear error message, and the test covering it is
recorded as skipped in plain view rather than passing quietly. The built-in store,
which keeps everything in ordinary files on the operator's own machine, is the
default and is fully functional.

**In live use, but not a universal gate.** The claim-checking component described in
section 12.4 is genuinely called at real points in the running system — when a
report is rendered, when a finding is written onto this map, at the end of an
engagement, by the reviewing components, and by the defensive gateway before it
issues a certificate. It is **not** a single checkpoint that every claim in the
system crosses; in particular, individual writes to this map are classified by the
shared grounding rule rather than routed through it. The written note inside that
component's own source file used to understate its use; it has since been corrected,
and an automated test now fails the build both if the retired "no callers" phrasing
returns and if a genuine caller is dropped from the list that note keeps.

---

## 18. Summary in plain terms

The system does not stop at a list of technical problems. It draws a living map of
the target — the machines, the accounts, the data stores, the cloud resources, the
defences, and who can reach what — and keeps it current as it learns.

Every entry on that map carries a permanent label saying where it came from and how
strongly it is believed, and the system keeps two separate belief measures so that a
failed re-check can actually move the number down. The map is built from an
append-only signed record and from nothing else, and it never reads the clock, so
anyone can rebuild it from the same record and get exactly the same answer.

A confirmed weakness is pinned onto the map — but on its own it grants an attacker
no movement: any claim that a weakness lets an attacker travel must be recorded as
its own statement, with its own evidence. From that base, the system reasons forward
using bounded, always-terminating rules and a catalogue of machine-checkable attack
techniques, and works out the routes from any starting point to the things the
organisation actually cares about. When the customer's cloud picture is folded in
afterwards, the route search is run a second time over the enlarged map, so a route
that only exists because of a cloud fact is not missed simply because it arrived
late.

It then answers the questions a decision-maker asks. How much is exposed from this
foothold. Which routes are most credible, and which are most corroborated. Which
single repair breaks the most attacks and protects the most value. And what would
still be exposed after that repair — stated in the same breath as the win.

The map is kept honest by re-running the original proof whenever a stored result is
used, and withholding everything downstream of any proof that no longer reproduces.
Withdrawals must themselves be evidenced. The map can authorise nothing: the
structures that hold it have no method to grant a permission or promote a claim, by
design.

And the parts that have not yet been pointed at somebody else's live cloud account
are named as such — here, in the interface, and in the machine-readable registry
that the system's own tests enforce.

---

## Notes and source references

These are kept out of the main text so the argument reads cleanly. They are here so
a technical reviewer can go straight to the code and check any statement in this
chapter.

[^1]: The asset map lives in the offensive engine at
`engine/crucible/framework/v2/worldmodel/`. The types of pin and arrow are defined
in `worldmodel/models.py`; the merge behaviour in `worldmodel/graph.py`; the
one-way build from the signed record in `worldmodel/spine_projector.py`; route
finding and chokepoint detection in `worldmodel/pathsearch.py`; the worth file and
the "what if we fixed it" calculation in `worldmodel/impact.py`; the command-line
report in `worldmodel/attack_paths.py`.

[^2]: For a technical reviewer, the source labels are short text strings and the
tier is read from the opening word. Labels beginning `oracle:`, `cert:`,
`finding:` or `evidence:` classify as *grounded*. Labels beginning `intel:`,
`intel-fused:`, `derived:`, `infer:`, `scan:` or `fingerprint:` classify as
*intel*. Labels beginning `llm`, `assume`, `guess`, `hallucin`, `unverified`,
`ungrounded`, `advisory` or `demoted` classify as *ungrounded*. Anything else is
*unclassified*. The classification is done by a single function,
`classify_provenance` in `worldmodel/models.py`, which the claim-checking component
of section 12.4 reuses rather than reimplementing.

[^3]: The worth file is `targets/<engagement>/impact.yaml`, loaded by
`worldmodel/impact.py`. Absent, unreadable or malformed, the loader returns the
uniform model rather than raising.

[^4]: The command is
`python3 -m framework.v2 attack-paths <engagement> --spine <record> --source
<starting point>`. It writes `attack-paths.md` for a person to read and
`attack-paths.json` for other software to read.

[^5]: The four live at `engine/crucible/framework/v2/worldmodel/` (the asset map),
`integration/vigil_integration/graph/` (the attack-chain view),
`engine/crucible/framework/v2/graph/` (the per-job partition — in the engine, not
beside the attack-chain view) and
`integration/vigil_integration/chainast/` (the reasoning-chain structure). The
second route search of section 7.4 is `framework/v2/scanner/lateral.py`, called
from `framework/v2/engage.py`.

[^6]: The fifth picture — the sovereign side's own graph — lives at
`apps/sigil/sigil/graph/`: the node and edge definitions in `graph/schema.py`, the
replay-into-a-fresh-copy-and-swap rebuild in `graph/rebuild.py`, and the read-only
query layer in `graph/query.py`. The determinism and provenance test is
`apps/sigil/tests/test_graph.py`. The refusal to load offensive code into a sovereign
process is `assert_no_offense` in `apps/sigil/sigil/reuse/`; a checker should expect to
find it called from the personal side's main subsystems and not from `graph/`, which is
the limit stated above.
