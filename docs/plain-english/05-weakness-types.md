# Every Type Of Weakness The System Can Find

## What this chapter is

This chapter is the complete catalogue. It lists every category of security weakness the system
recognises by name, what each one means in ordinary language, what an attacker could actually do with
it, and — just as important — the honest boundary of what the system proves about it.

Nothing here is a sample or a highlight reel. Every item in the system's internal vocabulary appears
below. Where the system can only go part of the way, that is stated beside the capability itself, not
hidden in a footnote. Two further things the system measures but does **not** treat as proven findings
are included as clearly-marked boxes rather than left out, because leaving them out would let a reader
believe the subject was never examined.

Eight counts frame the whole chapter. Every one of them was re-derived directly from the working
code, not copied from a brochure:

| What is being counted | Number |
|---|---:|
| Named types of weakness the system recognises (its master list) | 85 |
| Alternative spellings and industry synonyms it also accepts and files under one of the 85 | 190 |
| Total accepted names for a weakness (the 85 plus the 190) | 275 |
| Automatic decision procedures ("oracles") that can turn a suspicion into a proven finding | 38 |
| Separate defensive detection procedures that prove an attack happened, from the customer's own logs | 12 |
| Registered evidence windows — the specific channels through which a claim may be proved | 26 |
| …of those, windows that may currently state a proven **negative** ("this is not there") | 6 |
| Categories in the *separate* vocabulary used when testing a customer's own AI feature (Part 1, Family 15) | 14 |

The last row needs one sentence of explanation up front, because it is the one place where two
different lists exist. The 85 names are the master list used by the main testing engine. Testing a
customer's own artificial-intelligence feature is done by a separate component that uses the security
industry's own published list of AI weaknesses, which has 14 categories. Those 14 are *not* part of
the 85, and the chapter says so again where they appear.

---

## How to read every entry in this chapter

### The four words the system is allowed to say

Every result the system produces carries exactly one of four verdicts. This is not a style guide; the
list of four is enforced by the software itself, so no fifth word can appear.

| Verdict | Plain meaning | What it takes to earn it |
|---|---|---|
| **FACT** | We established this. | The system's own automatic test re-derived the result from evidence the system itself captured, and the sealed record of that result can be re-checked later by anyone, offline, without trusting us. |
| **LEAD** | Something suggests this. We did not prove it. | Anything weaker: another tool's opinion, a rule of thumb, an AI model's suggestion, a pattern match over text we cannot fully parse. |
| **CLEAN** | We looked properly, and this weakness is not present here. | We had a real channel to observe through, the evidence for that specific question was genuinely available, and the automatic test decisively refuted the weakness. |
| **INCONCLUSIVE** | We could not tell. | Everything else. This is a real result in its own right. It is never quietly rounded up into "clean". |

Two of these matter enormously to a buyer and are easy to confuse. **FACT** and **CLEAN** are both
statements about a specific target, specific inputs, and a specific window of time. Neither is a
timeless property of the system being tested. A FACT means "on this date, against this system, in
this configuration, this was true". A CLEAN means the same about a negative.

The written doctrine the engineering team holds itself to puts the reason bluntly:

> Asserting a vulnerability that is not there destroys trust in every finding. Asserting safety that
> was not established is worse, because nobody goes looking again.

### "Weakness type" and "oracle" — the two words you need

A **weakness type** (the code calls it a "bug class") is simply a named category, like "SQL
injection" or "misconfigured cloud storage". It is a label, nothing more.

An **oracle** is the automatic decision procedure that judges whether that weakness was really
established. Think of it as a laboratory test with a fixed, published protocol. It does not go and
collect the sample; something else does that. The oracle looks only at the sample that was collected
and returns a verdict by a fixed rule.

Five properties of these oracles matter to a procurement decision, and all five are structural
properties of how they are written, not promises:

- **They send no traffic.** An oracle never touches the target. It only judges evidence someone else
  already gathered.
- **They are deterministic.** The same evidence always produces the same verdict. There is no random
  element, no clock, no network lookup.
- **They work offline.** Anyone holding the evidence can re-run the same test on a disconnected
  laptop and get the same answer.
- **Missing input means "skipped", never "passed".** If the evidence an oracle needs is absent, the
  oracle does not run and does not vote. It never assumes the answer is good news.
- **They cannot claim certainty.** Confidence is capped at 0.99. A finding is only confirmed when at
  least one oracle fires at 0.70 or above.

### The handful of other words this chapter cannot avoid

Everything else in this chapter is written in ordinary English. These few words have no everyday
equivalent, so they are defined once here and then used plainly.

| Word | What it means in ordinary language |
|---|---|
| **Payload** | The test input the system deliberately sends, to see how the target reacts. Like tapping a wall to hear whether it is hollow. |
| **Marker** (also called a canary) | A short, unique, harmless string of characters the system makes up for one test only — the equivalent of a serial-numbered banknote handed to a suspect. If that exact string later turns up somewhere it should never be, the system knows precisely which test put it there. |
| **Sink** | The place where a piece of data finally *ends up doing something*: a database query, a command run on the server, a file the server opens, a piece of a web page a browser will run. A weakness almost always means untrusted input reaching a sink. Where this chapter says "a marker reached a sink", read: "the text we made up arrived somewhere it should never have been able to reach". |
| **Out of band** | Through a completely separate channel. An "out-of-band callback" means the customer's server made a connection to a machine the system controls — proof that something ran, arriving by a different road from the web page being tested. |
| **Evidence window** (the code calls it an evidence "branch") | The specific channel through which a particular claim may be proved — for example, "we saw this in the response headers" as opposed to "we saw this in the page text". Different windows support different strengths of claim. Part 4 uses this idea throughout. |
| **Fail closed** | If a check cannot be completed — a missing file, an error, an unreadable value — the answer is "no", never "probably fine". Like a drawbridge held up by power: cut the power and it falls shut. |

Three abbreviations also appear, and each is expanded here rather than in the tables that use them.
**IAM** stands for *identity and access management*: the part of a cloud account that decides who may
do what. **RBAC** stands for *role-based access control*: the same idea on a container platform, where
permissions are attached to named roles and roles are attached to people or programs. **TLS** is the
encryption that puts the padlock in a web browser's address bar.

### Why every table below has a "what it does not prove" column

This is the distinguishing feature of the system and the reason a national agency should care. Most
security tools report what they think they found. This system reports what it established *and* draws
the line where its own evidence stops. Those limits are written into the source code beside each test,
not bolted on afterwards. The tables below reproduce them.

---

## Part 1 — The 85 named types of weakness

The 85 types are grouped below into fourteen families a non-specialist can follow. Every one of the
85 appears exactly once. The "Proved by" column names the automatic test or tests that are permitted
to confirm that type; Part 2 explains each test.

A fifteenth family follows the fourteen. It covers testing a customer's *own* artificial-intelligence
feature from the outside — the attacker's side of AI security. It is set apart because it is run by a
separate component with its own list of category names, and those names are deliberately not part of
the 85. It is included here because a chapter titled "every type of weakness the system can find"
would be misleading without it.

Two further measurements appear as clearly-marked boxes inside families 3 and 8. They are real
capabilities in the software, they are reported, and they are honestly *not* among the 85 named types
because no automatic decision procedure confirms them. They are shown where a reader auditing coverage
against a standard checklist would look for them.

A structural safeguard runs underneath this entire list and is worth stating once. If the system ever
encounters a weakness label it does not recognise, it is **structurally incapable of confirming it as
a FACT**, even if one of its tests happens to fire. An unrecognised label fails closed. This means a
supplier, a plug-in, or an AI component cannot invent a new category of finding and have the system
stamp it as proven.

---

### Family 1 — Injection: when attacker text is treated as instructions

This is the oldest and still the most damaging family. The customer's software takes some text from
an outsider — a search box, a web address, an uploaded file — and, instead of treating it as plain
data, treats part of it as a command. The consequences range from reading the entire customer
database to running arbitrary programs on the customer's server.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `sqli` — SQL injection | The attacker's text is executed as a database query. In the worst case this reads, changes or deletes the whole database, including every customer record. | Database error signature, statistical yes/no probing, response differencing, out-of-band callback, or a marker reaching a place it must not |
| `boolean_sqli` — blind SQL injection by yes/no | Same underlying flaw, but the database answers are invisible. The attacker reconstructs the data one yes/no question at a time by watching tiny differences in the page. Slow, but complete. | Statistical yes/no probing, response differencing |
| `time_based_sqli` — blind SQL injection by delay | Same again, but the attacker reads the answer from how long the server takes to reply — a deliberate pause means "yes". Works even when the page never changes. | Statistical timing test, response differencing |
| `error_based_sqli` — SQL injection that leaks through error messages | The database's own error text spills fragments of data or internal structure back to the attacker. | Database error signature, marker reaching a sink, response differencing |
| `time_based` — any blind weakness read purely from an injected delay | The general category for "the only signal is that the server paused when it should not have". | Statistical timing test |
| `nosqli` — NoSQL injection | The same idea against modern document databases (MongoDB-style) rather than traditional ones. Typically used to bypass a login or dump records. | Statistical yes/no probing, response differencing, error signature |
| `ldap_injection` — corporate directory injection | Injection into the query language used by corporate directory services. Often used to bypass authentication or enumerate staff accounts. | Statistical yes/no probing, response differencing, error signature |
| `xpath_injection` — XML query injection | Injection into the query language for XML documents. Same consequences: data disclosure and authentication bypass. | Statistical yes/no probing, response differencing, error signature |
| `command_injection` — operating-system command injection | The attacker's text is executed as a command on the server's operating system. This is effectively a foothold on the machine. | Out-of-band callback, marker reaching a sink |
| `time_based_command_injection` — blind command injection | Same, but with no visible output; the attacker confirms it by making the server pause. | Statistical timing test, out-of-band callback |
| `rce` — remote code execution | The general category for "the attacker runs their own code on the customer's server". The most severe outcome in web security. | Out-of-band callback, marker reaching a sink, memory-safety crash marker |
| `ssti` — server-side template injection | The customer's page-building engine evaluates the attacker's expression. Frequently escalates to full code execution. | Proof that the server actually computed the injected expression, marker reaching a sink, response differencing |
| `el_injection` — expression-language injection | The same problem in enterprise Java-style frameworks. | Proof of evaluation, marker reaching a sink |
| `ssrf` — server-side request forgery | The attacker makes the customer's own server fetch a web address of the attacker's choosing. This is the standard route into a private internal network from the outside, and the standard route to cloud credentials. | Out-of-band callback |
| `xxe` — XML external entity | A malicious XML document persuades the server to read local files or make outbound connections. | Out-of-band callback, marker reaching a sink |
| `blind_xxe` — XML external entity with no visible output | The same, where the stolen data must be sent out over a side channel because nothing appears on the page. | Out-of-band callback |
| `deserialization` — unsafe object reconstruction | The server rebuilds a data structure from attacker-supplied bytes and, in doing so, runs attacker logic. A classic route to full server compromise. | Out-of-band callback, memory-safety crash marker |
| `path_traversal` — escaping the intended folder | The attacker walks up the directory tree and reads files the application never meant to serve: password files, configuration, private keys. | Marker reaching a sink (specifically, the target file's real contents appearing) |
| `lfi` — local file inclusion | A closely related flaw where the application is tricked into loading a local file as if it were part of the program. | Marker reaching a sink |
| `xss` — cross-site scripting | The attacker's script runs inside another user's browser session. Used to steal sessions, impersonate staff, or silently alter what a user sees. | Proof that the injected marker landed in a position a browser will execute |
| `dom_xss` — cross-site scripting that happens entirely in the browser | The same outcome, but the flaw is in the page's own browser-side code rather than the server. Hard to find with traditional scanning. | Proof that injected code actually executed inside a real browser, marker reaching a sink |

**Honest limits for this family.** Confirming any of these requires the system to obtain a real,
specific signal — a database error the attacker provoked, a computed arithmetic result, a callback to
a server the system controls, or code genuinely executing in a browser. The system deliberately does
**not** confirm on the mere appearance of an attacker's text in a page. That was changed on purpose:
three of the built-in checks (template injection, path traversal, error-based injection) used to
confirm on simple echo-back, which produced false alarms on any page that repeats what you type. They
were rewritten so that template injection only confirms when the server actually *computed* the
arithmetic, path traversal only when the *contents* of the target file appear, and error-based
injection only when a database error appears in the attack but *not* in a harmless control request.

---

### Family 2 — Proven attempted injection (judged from the request alone)

These three exist for a different purpose from the rest of the catalogue. They are used by the
system's protective, in-line mode, which inspects incoming requests to a customer's application in
real time. They judge the *request only*; they never see the application's answer.

The distinction is deliberate and important. These prove that a hostile construct was genuinely sent.
They make **no claim** that the customer's application was actually exploited — a properly built
application receives these attacks harmlessly every day.

| Weakness | Plain meaning | Proved by |
|---|---|---|
| `sqli_attempt` — attempted SQL injection | A submitted value provably closes off a database text field and starts adding query structure of its own (an always-true condition, a `UNION SELECT`, a second stacked statement, a terminating comment). | SQL break-out parse-proof |
| `command_injection_attempt` — attempted command injection | A submitted value contains an unambiguous operating-system command-execution construct — a shell substitution, or a separator followed by a real command with a real argument. | Command break-out parse-proof |
| `nosql_injection_attempt` — attempted NoSQL operator injection | A submitted value smuggles a known database query operator into a position where the application expected a plain value. | NoSQL operator break-out parse-proof |

**Honest limits.** Each of these is engineered to stay silent on legitimate look-alikes, because a
false alarm in in-line protective mode means blocking a real customer. Ordinary apostrophes in names
and prose do not fire the SQL test. A price written as `$5.00`, a regular expression, or the word
"select" in ordinary writing do not fire. A lone ampersand in a web address does not fire the command
test. These are structural tests, not keyword lists.

---

### Family 3 — Access control and business logic: doing things you should not be allowed to do

Here nothing is technically "injected". The application simply fails to check whether the person
asking is entitled to what they are asking for. In practice this family is the most common source of
real-world data breaches, because it needs no technical sophistication — just changing a number in a
web address.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `idor` — insecure direct object reference | Change the record number in the address and you see somebody else's record. Invoices, medical notes, case files. | Achieved-state test |
| `bola` — broken object-level authorisation | The programming-interface name for the same flaw, applied to machine-to-machine interfaces. | Achieved-state test |
| `bfla` — broken function-level authorisation | An ordinary user can call an administrator-only function simply by knowing its address. | Achieved-state test |
| `broken_access_control` | The general category: an access-control check is missing or ineffective. | Achieved-state test |
| `authorization` | The generic label for an authorisation failure. | Achieved-state test |
| `auth_bypass` — authentication bypass | Logging in is not required at all; the protection can be walked around. | Achieved-state test, response differencing |
| `mass_assignment` — client-supplied field writes a protected attribute | A user submits an extra hidden field — `"role": "admin"`, `"balance": 100000` — and the application saves it. | Achieved-state test |
| `privilege_escalation` | A low-privilege actor reaches a state that should require higher privilege. | Achieved-state test |
| `business_logic` — workflow abuse | The steps of a business process are performed out of order, repeated, or with tampered values: skipping a payment step, replaying a one-time discount, changing a price or quantity. | Achieved-state test |
| `request_race` — timing/concurrency abuse | Two requests are fired at the exact same instant so that a "once only" check is passed twice — for example, redeeming one voucher twice, or withdrawing the same balance twice. | Achieved-state test |

**Honest limits.** Three things in this family need the operator's involvement and do not run by
default:

- The access-control tests (`idor`, `bola`, `bfla`, `broken_access_control`, `mass_assignment`)
  require the operator to supply two genuine identities and to name which reference the test should
  swap. Without that, the system cannot tell "you may see this record" from "you may not". It does not
  guess. The source code states the reason without hedging: a broken-access-control test is
  fundamentally a two-identity experiment, and there is no honest way to discover the second identity
  automatically.
- `business_logic` is opt-in and requires the operator to describe the intended workflow. A machine
  cannot infer what a business process is *supposed* to do; the system therefore asks rather than
  invents.
- `request_race` is opt-in.

**The precondition behind this whole family: the system has to be logged in.**

Most of a real application's attack surface sits behind a login screen. The system can therefore hold
a genuine logged-in session on the customer's own application while it tests. The operator supplies
the test account's credentials and the address of the login page; the system then keeps a store of the
session cookies the application issues, sends every subsequent request with them, notices when the
session has expired or been dropped (the application answers "unauthorised" or "forbidden", or the
page shows a signed-out marker the operator named), logs in again, and repeats the request. All of
this traffic still goes through the same permission gate as everything else — the login machinery adds
no new route to the network.

Two honest notes on it. First, this is what makes the access-control family workable at all: the
"second identity" the tests need is a second logged-in session of the same kind. Second, in the
version read for this briefing this is a component of the testing engine rather than a field on a
form: neither the assessment wizard on the screen nor the command that launches an engagement offers a
place to type a target application's username and password. Supplying one today means configuring the
engine directly. An agency planning an assessment of a logged-in application should confirm with the
operator how those credentials will be supplied.

**A measurement that sits beside this family, and is deliberately not one of the 85: predictable
session tokens.**

When you log in, the application gives your browser a long random-looking string — the session token —
and from then on that string *is* you. If the string can be guessed or predicted, an attacker becomes
you without ever knowing your password. The system contains a measurement for exactly this. It
collects a set of freshly issued tokens and looks for the unmistakable weaknesses: the tokens simply
count upwards, the same token comes back twice, most character positions never change, or the tokens
are drawn from a tiny alphabet. It reports a lower-bound estimate of how much genuine randomness the
tokens contain.

Its honest boundary is written into its own source: this is a *measurement over the tokens observed*,
not one of the automatic decision procedures, so it carries a verdict of its own rather than producing
a proven finding in the sense this chapter uses everywhere else. A result of "no weakness found" means
no weakness was found in that sample. It is expressly not a certificate of cryptographic strength,
which would need thousands of samples. Because it is not judged by one of the 38 procedures, it does
not appear in the list of 85, and a finding from it is reported as a lead for a human to weigh.

---

### Family 4 — The web and protocol surface

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `open_redirect` | The customer's own site bounces a visitor onward to an address the attacker chose. Used to make phishing links look genuine, because the link really does start at the trusted domain. | Achieved-state test |
| `cors` — cross-origin resource sharing misconfiguration | The application tells browsers it is safe for a hostile website to read the customer's data using the victim's logged-in session. In effect, any website can read the victim's account. | Achieved-state test |
| `host_header_injection` | The application trusts the address the *client* claims to be visiting when building links, so password-reset emails and similar can be pointed at an attacker's server. | Achieved-state test |
| `request_smuggling` | A front-end system and a back-end system disagree about where one request ends and the next begins. The attacker slips an extra hidden request into another customer's connection. | Response differencing |
| `cross_site_websocket_hijacking` | A live two-way connection accepts a caller from a hostile website while carrying the victim's credentials. | Achieved-state test |
| `websocket_injection` | Injecting hostile content into a live two-way message stream. | Marker reaching a sink, response differencing |
| `exposure` — information disclosure | Something internal is reachable that should not be: a configuration file, a source-control directory, a diagnostic page, an internal listing. | Achieved-state test |
| `sensitive_exposure` — sensitive data exposure | The same, where what is exposed is genuinely sensitive data. | Achieved-state test |
| `security_misconfiguration` | An unsafe setting that is reachable over the application surface. | Achieved-state test |
| `jwt` — a forged access token was accepted, live | The application accepted a security token that was tampered with or had its signature removed. Whoever can do this can log in as anybody. | Achieved-state test |

**Honest limits.** For the redirect, cross-origin and host-header categories, the system distinguishes
carefully between *how* it saw the problem. Proving it from the response headers is a stronger
position than proving it from the page body, because the body may be compressed or encoded in ways
that cannot be read with complete confidence. Part 4 sets out exactly which of these may state a
proven negative and which may not. `request_smuggling` and the two live-connection categories are
opt-in modules, not part of a default run.

---

### Family 5 — GraphQL interfaces

GraphQL is a modern style of programming interface where the client describes exactly what data it
wants. It is powerful, and the same power makes it easy to expose or overload.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `graphql_introspection` | The interface will hand any anonymous caller a complete map of every data type and operation it supports — a blueprint of the system. | Achieved-state test |
| `graphql_suggestions` | Even with the map switched off, the interface's "did you mean…?" helpfulness leaks the same blueprint field by field. | Achieved-state test |
| `graphql_depth_limit` | A deeply nested query was accepted and executed with no depth guard. A single request can be made to consume enormous server resources. | Achieved-state test |
| `graphql_alias_overloading` | The same expensive operation was requested many times inside one request under different names, and all of them ran. | Achieved-state test |
| `graphql_batching` | Many operations were bundled into one request and all executed — often used to defeat rate limits on login attempts. | Achieved-state test |
| `graphql_cost` | Query cost or complexity abuse in general. | Achieved-state test |

**Honest limit worth stating plainly.** For query cost, the system's scanner deliberately keeps the
result as a LEAD rather than a proven fact. The reason is written into the code: the fact that a small
probe query was accepted cannot prove that a cost limit is *absent*. That would be an argument from
silence, and the system does not make those.

---

### Family 6 — Single sign-on and identity tokens

Single sign-on is the mechanism that lets staff log in once and reach many systems. If it can be
forged, an attacker becomes any employee, including administrators, across every connected system at
once. This family is therefore small but unusually severe.

The system keeps two very different questions strictly apart, and refuses to blur them:

- **Forgeability** — "this captured token could be forged by anyone holding it, and here is the
  offline arithmetic that proves it". No traffic is sent.
- **Acceptance** — "we sent a forged token to the customer's own system and it was accepted". This
  is a live test against the operator's own service.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `saml_signature_wrapping` | A live test: the customer's system accepted a login assertion whose signature had been structurally shuffled so it no longer covers the identity being used. The attacker logs in as anyone. | Achieved-state test (live) |
| `saml_assertion_tampering` | A live test: an altered login assertion was accepted. | Achieved-state test (live) |
| `oidc_redirect_uri` | A live test: the login endpoint will send the freshly issued credential to an address the attacker supplied. | Achieved-state test (live) |
| `oidc_idtoken_forgery` | A live test: a forged identity token was accepted. | Achieved-state test (live) |
| `jwt_forgeable` | An offline test on a captured token alone: the token can be forged by anyone. Three specific proofs are accepted — the token declares "no signature at all"; its signature can be exactly recomputed from a weak or supplied secret; or its signature verifies when a *public* key (which anybody may hold) is used as the secret. | Structural token-forgery test |
| `saml_structural_forgery` | An offline test on a captured login assertion alone: the assertion is unsigned, or its signature demonstrably covers a different part of the document than the identity being consumed. | Structural assertion-forgery test |

**Honest limits.** The two offline tests are deliberately coarse and conservative. Fully checking the
signature mathematics on a sign-on document is explicitly out of scope, and the reason is worth
spelling out because it recurs later in this chapter.

A signature on this kind of document is not calculated over the document as it arrives. It is
calculated over a *tidied-up* version of it: spacing, the order of attributes, and other formatting
choices are first rewritten into one agreed, exact form, and only then is the signature computed. The
technical name for that tidying step is **canonicalisation**. The comparison is a legal document that
must be retyped to an exact house style before it is stamped — the stamp certifies the retyped copy,
not the draft. Reproducing that step faithfully requires a full document-processing library, and the
system does not assume such a library is present. Rather than approximate the step and risk a wrong
answer in either direction, it declines to make the claim. There is an
opt-in escalation: if the operator supplies the genuine, trusted certificates of their identity
provider *and* the required library is installed, the system will perform a real signature check — but
it will only report a finding when a signature is *definitively invalid*, it will never trust a
certificate that came embedded in the document itself, and if it cannot verify, it refuses rather than
guessing.

---

### Family 7 — Memory safety in compiled software

These apply to compiled programs — device firmware, native binaries, embedded systems — rather than
web pages.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `memory_corruption` | The program writes outside the memory it owns. Classically the route to taking control of the program. | Memory-safety crash marker |
| `buffer_overflow` | The specific and best-known form: more data is written into a fixed-size space than fits. | Memory-safety crash marker |
| `use_after_free` | The program keeps using memory it has already released, which an attacker can arrange to have refilled with their own data. | Memory-safety crash marker |
| `crash` | The program terminates abnormally on attacker-supplied input. At minimum a denial of service; often the visible tip of a deeper flaw. | Memory-safety crash marker |

**Honest limits.** The confirming test looks for genuine memory-safety diagnostic output captured
from the program — the markers produced by standard address/memory/thread/undefined-behaviour
sanitisers, stack-protection aborts, or a hard segmentation fault. A plain application error message
is treated as only moderate evidence, because ordinary handled errors look similar. This family
proves that a crash of a certain kind occurred; it does not, by itself, prove that the crash is
weaponisable into code execution.

---

### Family 8 — Network exposure, encryption and supply chain

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `service_reachable` | A network service really is open and answering from where the system is testing. Confirmed by the system completing its own connection, not by reading a scanner's report. | Connection handshake test |
| `anonymous_reachable` | A resource can be fetched with no credentials whatsoever — genuinely public. Used to turn "the configuration says this is public" into "we fetched it, anonymously, and here is the response". | Anonymous-fetch test |
| `weak_tls` | The encrypted connection genuinely negotiated an obsolete protocol version or a weak cipher. Traffic protected this way is materially easier to intercept or tamper with. | Encryption handshake test |
| `weak_crypto_artifact` | A digital certificate is signed using a hash algorithm now known to be forgeable (MD2, MD4, MD5 or SHA-1). Such a certificate can, with effort, be counterfeited. | Certificate-signature test |
| `vulnerable_dependency` | A specific pinned version of a third-party software component falls inside the affected range of a published security advisory. | Version-range membership test |

**Honest limits.** Two of these need care in a briefing:

- The encryption test is scoped to what a modern client will still negotiate. It does not enumerate
  every historical cipher suite the server might theoretically accept. Its finding is "this weak
  option was actually negotiated", not "these are all the weak options available".
- The dependency test proves *membership in an advisory's affected range*. It does **not** prove the
  flaw is reachable or exploitable in the customer's specific use of that component. Equally, no
  match found is **not** the same as "no vulnerability": the advisory snapshot has a date and a
  boundary, and version constraints that are not pinned to an exact number are skipped rather than
  guessed at.

**A measurement that sits beside this family, and is deliberately not one of the 85: exposure to
future quantum decryption.**

A government reader will ask about this specifically, so it is stated here rather than left out.

The concern is not that a quantum computer will break today's encryption today. No machine capable of
that is known to exist. The concern is **record now, decrypt later**: an adversary with resources
records a customer's encrypted traffic today, stores it, and decrypts it years from now when such a
machine does exist. Whether that works depends on one specific part of the encrypted conversation —
the key exchange, the opening handshake in which the two ends agree on a secret. If that handshake
used the classical mathematics in wide use today, recorded traffic stays vulnerable to a future
machine. A forged signature, by contrast, has to be produced live, so signatures are a future
*impersonation* problem rather than a recording problem. The system's own source makes exactly this
distinction.

What the system does: it classifies the names of the encryption methods a server uses into four
buckets — classically vulnerable, quantum-resistant, a hybrid of the two, or unrecognised — and it can
make one real, bounded encrypted connection to a named host and report what an ordinary client
actually got. Its own first paragraph states plainly that **nothing here runs, simulates or requires a
quantum computer**; the word "quantum" describes the threat being reasoned about, not the hardware
doing the reasoning.

Its honest boundary is unusually well drawn and is reproduced here in full because it changes what the
result may be used for. The standard programming library this probe uses cannot ask a server for the
quantum-resistant options, and does not report which option was finally chosen. So the probe can prove
that a server **will accept** a classically vulnerable key exchange when an ordinary client asks — which
is the right question for the record-now-decrypt-later risk, because ordinary clients are what generate
the traffic being recorded. It **cannot** prove that a server lacks quantum-resistant support for
clients that can ask for it. Anyone quoting this output inside an assurance or approval decision must
respect that distinction. Because no automatic decision procedure adjudicates it, this is not one of the 85 named
types and its output is a report, not a proven finding.

---

### Family 9 — Cloud accounts, permissions and credentials

This family covers the customer's cloud environment: who can reach what, and whether stolen keys
actually work. Several entries below carry the letters **IAM** — identity and access management, the
part of a cloud account that decides which person or program may do which thing to which resource.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `privilege_path` | There is a real chain of permission grants by which one account can reach a sensitive resource. The chain itself, hop by hop, is the evidence. | Permission-path test |
| `iam_privilege_escalation` | Privilege escalation expressed as reachability: this identity can get to a more powerful position. | Permission-path test |
| `excessive_privilege` | An account holds more access than it needs, demonstrated by an actual path rather than a rule-of-thumb score. | Permission-path test |
| `iam_escalation_primitive` | A stronger claim than the three above: the configuration unconditionally permits a specific, named escalation manoeuvre that **strictly increases** what the account can reach. The evidence is an explicit before-and-after comparison — the target is reachable after the manoeuvre and provably not reachable before it. | Escalation-primitive test |
| `cloud_misconfiguration` | An explicitly unsafe achieved state on a single cloud control: encryption at rest switched off on a sensitive data store, an explicit "public: true" flag, a wildcard or anonymous party named in the resource's own access policy, or a named party from an account outside the customer's own. | Cloud achieved-state test |
| `imds_credential_capture` | Cloud machine credentials were actually retrieved from the internal metadata service **and** proven to work. This is the classic escalation from "the server can be made to fetch a URL" to "we now hold the server's cloud identity". | Metadata-credential test |
| `secret_credential_validity` | An exposed secret — a key found in a file, a page, or a code repository — was proven to be **still valid** by authenticating with it as a real identity. | Secret-validity test |
| `gcp_sa_impersonation` | An account minted a short-lived credential **as** a different named service identity, and an independent check confirmed the new credential really carries that other identity. | Impersonation test |

**Honest limits, stated precisely.**

- The "named party from an outside account" rule only produces a proven fact when the operator has
  supplied the list of their own account identifiers from the signed engagement charter. With no such
  list, the result stays a LEAD. The system never guesses who owns an account.
- For one specific cloud provider construct — Google-managed service agent identities — the system
  deliberately refuses to make a cross-account claim at all, because those identities cannot be
  reliably distinguished or enumerated, and any list would fail in the unsafe direction.
- The escalation-primitive test refuses to contribute evidence whenever a policy statement is
  conditional, ambiguous, subject to an explicit denial, restricted by a permissions boundary or an
  organisational policy, or where a wildcard does not actually cover the target. It also states its
  own residual limit openly: effective cloud permission is the intersection of several policy layers,
  and a resource-side policy not present in the captured evidence could still cancel the permission
  it observed.
- The metadata-credential test's own code carries the honest note that firing proves the capture is
  *structurally consistent* — a valid credential from a genuine metadata endpoint, plus a successful
  confirming identity call with no failure marker anywhere in it. Binding that specific credential to
  that specific call, and vouching for where the evidence came from, is the job of the controlled,
  approval-gated collection step, not of the offline test.
- The secret-validity test deliberately does **not** treat the *source* of the secret as a condition
  for firing. It claims validity, not provenance. It also never stores or inspects the secret's actual
  content — only a redacted presence marker and a fingerprint. Crucially, the "confirming" call must
  be made to an endpoint on a fixed approved list, so an attacker-controlled server cannot be used to
  manufacture a false confirmation.

---

### Family 10 — Kubernetes and service mesh

Kubernetes is the software that runs modern container platforms. A service mesh is the layer that
controls how services inside such a platform talk to each other.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `k8s_misconfiguration` | A platform control-plane benchmark check hard-failed **and** the captured value literally contains a dangerous setting — anonymous access enabled, authorisation set to "always allow", an insecure port left open, or a static credentials file in use. | Platform benchmark test |
| `k8s_workload_misconfiguration` | An **anonymous** (unauthenticated) identity is bound to a genuinely dangerous built-in administrative role. In plain terms: anyone at all who can reach the platform has administrative rights. | Anonymous role-binding test |
| `k8s_rbac_privilege_grant` | A stronger, deeper version of the above: the actual permission rules of the role were parsed and shown to grant a dangerous capability — a total wildcard, the ability to read all secrets, or the ability to escalate, bind or impersonate — to an identity an attacker could realistically occupy. | Permission-rule grant test |
| `mesh_misconfiguration` | The service mesh's configuration **declares** a permissive state: mutual encryption set to permissive or disabled, an "allow" policy that admits every caller, or a default inbound policy of "all unauthenticated". | Mesh configuration test |

**Honest limits.** These are important and specific.

- All four judge a **captured export**, not a live cluster. An export is a partial, point-in-time
  snapshot of what was handed to the system.
- The benchmark test ignores advisory "warn" results — those become LEADs for human review — and
  refuses to fire when a failure carries no captured value or where the captured value actually shows
  the *secure* setting.
- The anonymous role-binding test explicitly does not fire on the harmless built-in public-information
  role, on an anonymous binding to a custom or non-dangerous role, on a locally scoped role that
  merely happens to be *named* "admin", or on a service account merely *named* like an anonymous one.
- The permission-rule test uses a deliberately narrow eligibility gate. In plain terms, *who* holds the
  dangerous power decides how strong a claim the system is willing to make about it. A truly anonymous
  identity — anyone at all, with no credentials — may produce a proven fact on any dangerous shape. But
  the platform's default service account, or the "all authenticated users" group, may only produce a
  proven fact on a *total* wildcard grant delivered across the whole cluster — never on secret-reading
  and never on escalation rights. The reason is written into the code: the standard built-in "admin"
  role legitimately grants secret reads, and ordinary backup and monitoring roles legitimately grant
  broad read access, so treating those as findings would raise false alarms in almost every real
  cluster. Those cases stay LEADs.
- One point of wording, because it matters to a procurement reader. The source code calls that gate its
  "near-zero-false-positive fix". That is the engineers' stated design intention, and this briefing
  repeats it as an intention. It is **not** a measured false-alarm rate: no such measurement exists in
  the project, and none is claimed here. What can be checked is the mechanism — the gate above, written
  out in full, and the list of cases the test refuses to fire on.
- The mesh test proves what the configuration **declares**, not the effective runtime behaviour.
  Policy precedence, namespace and workload selectors, and more specific overriding policies are not
  evaluated. Where a setting is absent and would be inherited from a parent, the system does not
  resolve the inheritance and therefore does not promote the result.

---

### Family 11 — Build pipelines and software supply chain

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `cicd_misconfiguration` | The automated build-and-deploy pipeline contains a dangerous construct: a third-party build step referenced by a movable label rather than an exact fixed version (so the supplier can silently change what runs); a pipeline that checks out and runs code from an untrusted outside contribution while holding write-capable secrets; or a pipeline command that pastes untrusted text from an outside contribution directly into a shell command. | Pipeline configuration test |

**Honest limits.** No repository is cloned and no pipeline is run. This is a careful reading of the
workflow file the operator supplied. It proves the dangerous construct is present; it does **not**
prove the pipeline was exploited. A build step pinned to an exact version, a first-party build step, a
pipeline triggered only by ordinary contributions, and a command containing only quoted literals do
not produce findings. It also cannot prove *absence*: one workflow file says nothing about other
workflow files, about reusable workflows it calls, or about composite build steps.

**The same discipline, turned on the system's own build.** A buyer is entitled to ask the obvious
follow-up question: this product tells me my build pipeline is unsafe — what about yours? The answer is
a set of build-and-release safeguards that were merged into the main line of the project on the day
this chapter was written. They exist because the ingredients of a piece of software are something an
attacker can change without ever touching its source code.

| Safeguard | What it means in ordinary terms |
|---|---|
| Exact-version, fingerprinted dependency locks | Every third-party package the system installs is recorded with its exact version *and* a cryptographic fingerprint of the exact file, for both of the system's two software environments. Installation runs with fingerprint checking switched on, so a package altered anywhere between the supplier and the build fails to install. The build proves that installation actually succeeds under that rule, rather than asserting it. |
| Container images pinned by content, not by label | An image label such as "latest" is a movable pointer: the publisher can change what it points at silently. Every image the project pulls from an outside registry is instead pinned to a fingerprint of its exact content, enforced by a check that needs no network. A second, networked mode reports where an upstream supplier has since moved on — information only, because an upstream change is not a fault in the change being reviewed. |
| A bill of materials for each environment | A machine-readable ingredients list, in a standard published format, generated for each of the two environments and published alongside the build. It is what lets a customer answer "does this product contain the component that was in the news this morning?" without asking the supplier. |
| A vulnerability gate that actually blocks | Every build is scanned for known vulnerabilities in those ingredients. A CRITICAL finding **blocks** the change from being merged. HIGH findings are reported in full but do not block, on the stated reasoning that a gate whose exception list has to grow without limit to stay green stops meaning anything. The scanner itself is pinned by version and by the fingerprint of its own release file. |
| Exceptions must be argued in writing | Suppressing a vulnerability finding requires a written justification beside it, drawn from a fixed list of five accepted reasons — no fix published upstream, the vulnerable path is not reachable in how the project uses the component, present only in test material, disputed upstream, or a scanner misidentification. A test enforces the rule and refuses a bare identifier with no reason. |
| A negative control on the gate itself | The build deliberately runs the blocking configuration against a sample known to contain CRITICAL problems, and requires it to fail. This is the same laboratory discipline the rest of this chapter describes: a check that cannot fail proves nothing when it passes, so the project proves its own gate can fail before trusting it to pass. |
| The project's own build steps pinned to exact commits | Third-party build steps run with the project's own credentials, so they are themselves third-party code. Each is pinned to an exact commit identifier rather than a movable label, and a test keeps it that way. |

Two honest notes. First, these safeguards concern how *this system* is built and released; they are not
a test performed against a customer. Second, this is a statement about the state of the repository at
the time of writing, on its main line. Anyone relying on it should check the current state of the
repository rather than take a document's word for it — which is the same standard this chapter applies
to every other claim in it.

---

### Family 12 — Mobile applications

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `mobile_misconfiguration` | The distributed mobile application ships with an embedded **private key** that is genuinely loadable and unencrypted. Because the application is on every customer's phone, that key is extractable by anyone who wants it. | Mobile artefact test |

**Honest limits — an unusually clear example of the system's discipline.** Exactly one mobile signal
is treated as provable. An internal adversarial review examined the obvious candidates — whether the
application permits unencrypted network traffic, whether it targets an outdated platform version,
whether a component is exported to other applications — and concluded that each of them depends on a
chain of platform precedence rules that the manifest file alone does not contain. All of those
therefore remain LEADs for a human to assess. The one remaining test proves itself by *actually
loading* the key material. An encrypted key, a public key, a certificate, a masked placeholder, or an
unparseable string all cause the test to refuse rather than assert.

---

### Family 13 — Corporate identity and email spoofing

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `identity_misconfiguration` | Either a privileged account with multi-factor authentication provably absent, or a credential that has never been rotated or is older than the organisation's own stated maximum age. Both are the standard preconditions for an account takeover that then spreads. | Identity-record test |
| `email_auth_misconfiguration` | The organisation's published email policy permits anyone to send email that appears to come from its domain — either no enforcement policy is published, the policy explicitly instructs receivers not to enforce, or the sender policy permits any host in the world. This is the technical precondition for convincing invoice fraud and executive impersonation. | Email-policy test |

**Honest limits.**

- The identity test refuses to fire when the multi-factor field is simply *absent*. A missing field is
  not proof that protection is missing. It also refuses to infer that an account is privileged from
  its role name; the person or system supplying the export must state it. Behavioural anomaly
  detection is explicitly out of scope, because it is probabilistic and cannot meet the standard for a
  proven fact. Account age is read from a stored number, never from a clock, so the result is
  reproducible.
- The email test proves only what the domain **publishes**. It deliberately does not attempt to check
  whether an individual message was genuine. Two obstacles make that unsound to re-derive after the
  fact. The signature on a single email is calculated over a tidied-up form of the message — the same
  "canonicalisation" step described in Family 6 — and messages are altered in transit in ways that
  cannot be undone reliably afterwards. And a sender policy may refer outward to other policies, which
  may refer outward again, so re-deriving it later needs live lookups whose answers may since have
  changed. The "authentication results" note stamped on a delivered message is only the receiving mail
  server's word for it, not evidence anyone else can re-check. Those remain LEADs. A missing sender policy alone does not fire, because other controls
  may still protect the domain. A subdomain that publishes nothing but inherits an enforcing
  organisational policy correctly does not fire.

---

### Family 14 — Defending the customer's own AI features and spotting automated abuse

These four are used in the system's *defensive* mode, pointed inward at the customer's own
applications and telemetry rather than outward at a target. They answer "is something happening to us,
and can we prove it?". The *offensive* counterpart — deliberately attacking a customer's own AI
feature to find its weaknesses before someone else does — is Family 15, immediately after this one.

| Weakness | Plain meaning and what an attacker gets | Proved by |
|---|---|---|
| `prompt_injection` | Text supplied by an outsider changed the behaviour of the customer's AI-powered feature — flipping a refusal into compliance, coercing a sensitive tool into running, or breaking the boundary between instructions and data. Attackers use this to make a customer's own AI assistant leak data or take unauthorised actions. | Prompt-injection differential test |
| `system_prompt_disclosure` | The customer's confidential system instructions leaked out verbatim through their own AI feature. Those instructions frequently contain business rules, internal system names, and guardrail logic. | Canary-disclosure test |
| `automated_access` | A non-human client fetched a decoy resource that no human interface links to. Evidence of automated crawling or scanning of the customer's site. | Honeypot-fetch test |
| `credential_stuffing` | A single source achieved statistically significant *successful* logins across many accounts it had never touched before — the signature of an account-takeover campaign using stolen password lists. | Credential-stuffing statistical test |

**Honest limits.**

- The prompt-injection test requires a genuine, structurally detectable behaviour change between a
  clean control conversation and the same conversation with the injected text. The presence of
  attacker-style phrasing alone — "ignore the above instructions" — is deliberately **not** enough,
  because real users legitimately paste such text into AI tools. Those remain LEADs.
- The disclosure test proves that a planted secret marker crossed the boundary into the AI's output.
  The marker is at least sixteen characters long and deliberately random enough that it could not be
  guessed, typed by accident, or produced by coincidence — a long, meaningless serial number rather
  than a word. Its appearance in the AI's answer is therefore proof that it travelled from the hidden
  instructions into the visible output. It does **not** prove that an *injection caused it*: an
  innocent request to repeat the instructions, or the application's own diagnostic mode, produces the
  same evidence.
- The automated-access test proves **automation**, not malice. Link-preview services, browser
  pre-fetching, antivirus URL scanners and uptime monitors all trigger it. The operator's allowlist is
  treated as a refutation.
- The credential-stuffing test can never confirm on failed logins alone. A burst of failures from one
  address — typical of many users behind a single corporate or mobile network gateway — produces no
  statistical round at all. It also raises its own bar in proportion to how many different sources it
  examined: if you look at ten thousand addresses, a few will look unusual purely by chance, so the
  evidence required from any single one is tightened accordingly. That is what stops sheer volume of
  searching from manufacturing a hit.
- The same test never sees a real username or a real network address. Before it runs, each of those has
  already been replaced by a **keyed pseudonym** — a stand-in code produced from the real value using a
  secret key held by the customer. The same username always produces the same code, so the test can
  still tell "this is the same account again" and "this is a different one", but the codes cannot be
  turned back into names or addresses by anyone who does not hold the key. It is the same idea as a
  hospital study that works from patient numbers rather than patient names.

---

### Family 15 — Attacking the customer's own AI feature (a separate vocabulary of 14 categories)

Family 14 defends a customer's AI feature. This family attacks it, on the customer's behalf, to find
what an outsider would find. It matters because organisations are now putting AI assistants in front
of staff and citizens, and those assistants can be talked into leaking data, ignoring their own rules,
or acting outside their remit.

**How it works, in ordinary terms.** Four established AI red-teaming tools exist in the industry —
garak, PyRIT, Giskard and promptfoo. Each fires large batteries of hostile prompts at an AI feature and
reports what it got away with. The system does not reimplement them and does not absorb them: it runs
whichever one the operator chose as a **separate program**, behind a boundary, and then reads the
report that program produced. This keeps the tools' heavy and conflicting software requirements out of
the system entirely, and it means the system never has to trust the tool's own judgement about what is
true.

**The categories.** Results are filed under the security industry's own published list of AI
weaknesses, not under the 85 names used elsewhere in this chapter. There are 14 of them. The right-hand
column is the part that matters for procurement, and it is explained immediately below the table.

| Category | Plain meaning | Can it ever become a proven finding? |
|---|---|---|
| Prompt injection | Outsider text talks the AI into ignoring the instructions its owner gave it. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Jailbreak | The same, aimed specifically at the AI's refusal rules — talking it past a "no". | **Yes** — a mechanical rule decides it, so it can be re-run |
| Encoding bypass | The hostile instruction is disguised (for example written in a coded alphabet) so that a filter waves it through and the AI still understands it. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Data disclosure | The AI hands out a secret it holds — an access key, an internal credential. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Personal-data leak | The AI hands out personal information about identifiable people. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Supply chain | The AI recommends or names software components that do not exist, which an attacker can then create and poison. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Training-data leak | The AI reproduces material from the data it was trained on, verbatim. | **Yes** — a mechanical rule decides it, so it can be re-run |
| System-prompt leak | The AI reveals the confidential instructions it was given by its owner. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Misinformation | The AI can be induced to assert things that are false. | **Yes** — a mechanical rule decides it, so it can be re-run |
| Harmful generation | The AI produces genuinely harmful content, such as malicious code. | **No** — another AI model decides it, so it stays a lead |
| Toxicity | The AI produces abusive or hateful output. | **No** — another AI model decides it, so it stays a lead |
| Hallucination | The AI confidently invents facts. | **No** — another AI model decides it, so it stays a lead |
| Bias | The AI's output shows stereotyping or unfair treatment. | **No** — another AI model decides it, so it stays a lead |
| Ethical violation | The AI breaches a stated ethical rule. | **No** — another AI model decides it, so it stays a lead |

**Why the last five can never be proven facts — and why this is the clearest example of the whole
product's discipline.** The first nine categories are decided by a mechanical rule: a specific phrase
must be present, a fixed pattern must match, or a fixed classifier must return a given label. A
mechanical rule can be *re-run*. So the system re-runs it — over the retained raw output of the tool,
with a fresh, unguessable challenge value minted for that one run — and only if that re-run comes back
with a signed reference to the evidence does the result become a proven finding.

The last five are decided by *another AI model acting as the judge*. There is no mechanical rule to
re-run: ask the judge twice and it may answer differently. The system therefore routes those results
to "lead" **before the checking step is even consulted**. That ordering is deliberate and is the point
of the design: because the decision is made before any check runs, no score, no severity rating, and
not even a compromised or hostile checking component could turn a judge's opinion into a proven fact.
The source states it as an invariant, and the project's internal adversarial reviews attack precisely
this path.

Three further protections are worth naming, each verifiable in the source:

- **The tool's own label is never trusted.** The category the outside tool reports is looked up in the
  system's own table; the label that ends up on the record comes from that table, never from the tool's
  text. So nothing an attacker could influence reaches the record.
- **An unrecognised category is treated as judge-decided, and can therefore only ever be a lead.** The
  open-source project this taxonomy was adapted from does the opposite: it treats an unknown category
  as mechanically checkable, which makes it eligible for promotion. The system deliberately inverts
  that. A category it has not classified is never routed onto the promotion path.
- **The success rate is a statistic, never a promotion signal.** These tools report how many of their
  attempts succeeded. That number is carried through as a measurement for triage. A success rate of
  100 per cent on a judge-decided category is still a lead.

Everything about the component is built to fail towards silence: no checking component wired, a
checker that errors, an empty or malformed reply, an unknown tool, or unreadable tool output all
produce leads or no signal at all — never a fact, and never a crash.

**Honest status, stated plainly.** The routing, the category table, the report readers, the boundary
that runs the tool as a separate program, and the fail-closed rules above are **built, and proven by
their own tests**. The four tools themselves — garak, PyRIT, Giskard, promptfoo — are **not installed
in the environment this briefing was written from**, and could not be installed there because that
machine has no route to the internet. In that state the adapter honestly reports the tool as
unavailable and returns nothing. **No proven finding has ever been produced from these tools here, and
none is claimed.** Live use is deferred until an operator provisions the tools. A further deliberate
restriction applies in the meantime: the shipped default permits the AI target to be on the same
machine only, and any other address is refused unless a deployment explicitly wires in the system's
general outbound-traffic gate.

This is exactly the distinction the whole briefing turns on: a capability that is built, reviewed and
constrained is not the same thing as a capability that has been fired in the field, and the two must
never be described in the same words.

---

### The 190 alternative names the system also understands

Security teams, tool vendors and standards bodies all use different words for the same weakness. One
supplier's report says "SQL injection", another says `sqli`, a third says `sql_injection`. The system
accepts 190 such alternative spellings and industry synonyms, and files every one of them under one of
the 85 master names above, so the same weakness cannot be counted twice or filed in two places because
two people wrote it differently. Every alternative name resolves to a master name; none is left
dangling.

**A general reader does not need the mapping itself.** It is 57 master names and their accepted
alternatives, and it is reproduced in full, with a plain-English meaning for each, in Appendix A at the
end of this chapter. The remaining 28 master names have no alternatives registered and are referred to
only by their own name.

---

## Part 2 — The 38 tests that turn a suspicion into a proven finding

Part 1 listed *what* the system looks for. This part lists *how it decides*. There are 38 of these
decision procedures. Each one is a fixed, published rule that anybody can re-run over the same
retained evidence.

One architectural fact underpins the trustworthiness of this list and is worth understanding. Only
**15** of the 38 form the general-purpose set. The other 23 are reachable **only** through an explicit
entry for a specific weakness type, and each of them additionally requires a piece of evidence with a
name that no ordinary web scan ever produces. The practical consequences are:

- Adding a new test to the system cannot change what an ordinary scan does or reports.
- None of the newer, more specialised tests can fire accidentally during a routine web assessment.
- The general-purpose set is deliberately frozen at 15 and does not grow.

One clarification, so the arithmetic is not misread. The re-checking step described in Family 15 — the
one that re-runs an AI red-teaming tool's mechanical rule with a fresh challenge value — is **not** one
of these 38. It is supplied to that component from outside rather than being part of this list, which
is why Family 15 says a result becomes a proven finding only when *that* component returns a signed
reference to the evidence. The 38 below are the procedures the main testing engine uses.

### The core 15 — the general-purpose set

| Test | What it establishes | What it deliberately does not establish |
|---|---|---|
| Response differencing | Two observed responses are materially distinguishable across status, length, wording, structure, timing or a planted marker. | *Why* they differ. And a single comparison showing no difference proves nothing — this test is one-sided. |
| Achieved state | A dangerous condition, evaluated over the raw observed values (headers, page bodies, statuses, identities); or an exact match against a state the attacker predicted in advance. | A partial match, which is treated as informational only. This test exists specifically so a check cannot approve its own conclusion. |
| Marker reached a sink | A unique, attacker-chosen marker of at least four characters arrived somewhere it must never reach. | That the marker is *executable* — that is a different test. |
| Out-of-band callback | A blind, invisible execution on the server: an incoming connection to infrastructure the system controls carried the secret token registered for this one finding. | Anything without that token. If there are no incoming connections, it does not fire; if there are connections but no registered token, it does not fire. |
| Memory-safety crash marker | A genuine memory-safety or crash diagnostic in captured program output. | A plain application error trace, which is only moderate confidence because ordinary handled errors look similar. |
| Statistical timing test | A genuine statistical test, not a stopwatch: three conditions that must hold together, over at least five measurements on each side. They are set out immediately below this table. | A finding based on a fixed rule such as "anything slower than two seconds counts", or on a single comparison of two averages. The code names this explicitly as what other tools largely do, and as the reason they raise false alarms. |
| Statistical yes/no probing | The same question asked repeatedly in a form whose answer should be "true" and a form whose answer should be "false", with evidence accumulating round by round until it crosses a boundary in one direction or the other. Set out immediately below this table. | A page that changes constantly — it trips the test's own built-in control. If neither boundary is reached, the result is inconclusive, never a guess. |
| Executable-position reflection | The planted marker landed somewhere a browser will execute it — it became part of a tag name, sits inside a script block, or landed in an event handler or a script-carrying link. Decided by parsing the page, not by pattern matching. | An encoded, commented-out, or plain-text appearance of the marker. Those are inert and correctly do not fire. |
| Evaluation | The server actually *computed* an injected expression: the computed answer appears, the raw expression does not survive intact, and the answer is absent from a harmless control request. | A payload that was merely reflected back without being computed. Ruling that out is the entire purpose of the second condition. |
| Error signature | A distinctive, engine-specific database or parser error that a malformed input provoked — MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, Java database connectivity, MongoDB, directory services, or XML query. | The generic word "error". And a page that *always* shows a diagnostic trace does not qualify, because the harmless control response must lack the same signature. |
| Browser execution | Injected code genuinely executed inside a real browser: a planted canary value appeared among the arguments passed to a callback function that only the system's own driver registered. The code describes this as the strongest available evidence for this weakness and close to unforgeable. | A reflected but inert or encoded payload, which produces no callback at all. |
| Connection handshake | A real network handshake was reproduced — a completed connection to the named host and port. A captured service banner raises confidence further. | Anything taken from another scanner's "open port" report. Notably, the connection's reported peer address does **not** raise confidence, because it simply returns the port that was dialled and is therefore self-referential. A connectionless protocol with no banner does not fire. |
| Encryption weakness | A real encrypted handshake negotiated a deprecated protocol version or a weak cipher; or a parsed certificate is signed with a broken hash algorithm. | That the server would accept *every* legacy option. It is scoped to what a modern client still negotiates. |
| Version range membership | A specific pinned software version provably falls inside a specific pinned advisory's affected range. Purely deterministic arithmetic on version numbers. | That the matching advisory is exploitable in this deployment. And absence from the advisory snapshot is not absence of vulnerability. An unparseable or empty range causes a refusal, not a guess. |
| Permission path | A real chain of permission grants, re-derived by walking the retained permission graph. The ordered list of hops *is* the evidence. | Another tool's judgement that something is "over-privileged", which is never trusted. An access token of unknown power is treated as read-level, never administrative. |

#### The two statistical tests, written out in full

Two entries in that table are the difference between this system and a conventional scanner, and they
deserve more room than a table cell.

**The timing test.** Some weaknesses have no visible symptom at all. The only signal is that the server
paused when it should not have — because the attacker's injected instruction told it to wait. A
conventional tool decides this with a rule of thumb: "anything slower than two seconds counts". That is
why such tools raise false alarms; ordinary servers are slow all the time, for ordinary reasons. This
system instead requires three things to hold at the same time:

- The slow answers must be *reliably* slower than the normal ones, not merely slower on average. One
  unlucky measurement can move an average; it cannot move a consistent ranking.
- The gap must be big enough to matter, not merely big enough to notice.
- Where it can be checked, asking the server for a *longer* pause must produce a *proportionally*
  longer wait. A genuine injected delay behaves that way. A server that is merely busy does not.

At least five measurements are taken on each side before the test will say anything at all. The
everyday comparison is a drug trial: a single patient feeling better proves nothing, and the question
is never "did it look different?" but "is this difference larger than chance would produce, and does a
larger dose produce a larger effect?"

**The yes/no probing test.** This is how the system reads data out of a system that never shows it
anything. It asks the same question in two forms — one whose answer should be "true" and one whose
answer should be "false" — and repeats. Evidence builds round by round until it crosses a boundary in
one direction or the other. The image to hold is a jury that keeps hearing witnesses until it is
genuinely sure, rather than deciding after the first one; and either verdict ends the process, so
"refuted" is as real an outcome as "confirmed".

A round only counts when two things are true together: the "true" question produced a different page
from the "false" one, **and** two separate "false" questions produced the *same* page as each other.
That second condition is the control. It screens out pages that simply look different every time you
load them — a rotating advertisement, a timestamp, a session identifier printed in the corner — which
is exactly the thing that fools a simpler comparison.

### The four defensive tests for AI features and automated abuse

| Test | What it establishes | What it deliberately does not establish |
|---|---|---|
| Prompt-injection differential | An injected directive flipped a structurally detectable behaviour compared with a clean control turn. | That attacker-style phrasing alone is a problem — that stays a LEAD. |
| Canary disclosure | A planted marker — at least 16 characters long and random enough that it could not be guessed or arrived at by chance — appeared word for word in the application's own AI output. | That an injection caused it. |
| Honeypot fetch | A client fetched a decoy resource that no human-facing interface links to. | That the client was malicious. |
| Credential stuffing | For each source separately, evidence accumulates round by round over *successful* logins to account-and-source pairings never seen before, until it crosses a boundary. Because many sources are examined at once, and a few will look unusual purely by chance, the bar each single source must clear is raised in proportion to how many were examined. | Anything from failed logins alone. |

### The three request-only parse-proofs

| Test | What it establishes | What it deliberately does not establish |
|---|---|---|
| SQL break-out | A submitted value provably closes a database text field and introduces query structure anchored to that break-out. | That the application was exploited. A properly built application is unaffected. |
| Command break-out | A submitted value contains an unambiguous command-execution construct. | Exploitation. |
| NoSQL operator break-out | A known database query operator was injected as a *key* where a plain value was expected. | Exploitation. The list of recognised operators is curated to exclude legitimate document keys and dual-purpose ones. |

### The ten posture tests — offline re-derivation over a retained document

Each of these reads a document the operator supplied or the system captured earlier, and re-derives a
conclusion from it. **None of them makes any live call.**

| Test | What it establishes | Bounded to |
|---|---|---|
| Platform benchmark (Kubernetes) | A control-plane benchmark check hard-failed with a concrete dangerous flag in the captured value. | The parsed export, never the live cluster. Advisory "warn" results become LEADs. |
| Anonymous role binding (Kubernetes) | An anonymous identity is bound to a dangerous built-in administrative role. | The bindings present in the supplied export. |
| Permission-rule grant (Kubernetes) | The role's actual rules grant a dangerous capability to an attacker-occupiable identity, with the role-reference link independently re-checked rather than trusted. | Rules that are authoritative — either fetched live from the platform, or a static file with no rule-aggregation directive. Aggregated static rules stay LEADs. |
| Cloud achieved state | One cloud control is in an explicitly unsafe state, evaluated in a fixed rule order. | The represented state. An ambiguous attribute is recorded as unknown, never guessed as unsafe. |
| Service mesh configuration | The mesh configuration declares a permissive state. | What is *declared*, not the effective runtime behaviour. |
| Pipeline configuration | The automated build instructions contain one of three dangerous constructs: a third-party build step referred to by a movable label rather than a fixed version, so the supplier can silently change what runs; a step that fetches and runs code from an outside contribution while holding secrets that can write to the customer's systems; or a step that pastes text from an outside contribution straight into a command the machine will execute. | The one build-instruction file examined. |
| Mobile artefact | The application embeds a private key that genuinely loads and is unencrypted. | This single rule. Every other mobile signal remains a LEAD by design. |
| Email policy | The published domain policy permits spoofing. | Published policy only, never message-level verification. |
| Identity record | A privileged identity with multi-factor authentication provably absent, or a stale or never-rotated credential. | Strictly typed literal fields in the export. An absent field causes refusal. |
| Structural token forgery / structural assertion forgery | A captured sign-on token or assertion is forgeable from the artefact alone. | Coarse structural checks only. Checking the signature mathematics itself — which first requires reproducing the document-tidying step described in Family 6 — is out of scope unless the operator opts in by supplying trusted certificates and installing the required library. |

### The six live-capture tests — the exploitation-confirmation tier

Each of these judges a captured record produced by a **separate, approval-gated collection step**. The
test itself never touches the network. All six are held out of the general-purpose set and require
evidence with a name no scan produces.

| Test | What it establishes | Deliberate limit |
|---|---|---|
| Anonymous fetch | A resource already assessed as public is provably fetchable by anyone — a bounded, credential-free request returned a success status with a non-empty body. | Does not fire on a redirect, on "unauthorised" or "forbidden" (which are the *opposite* of the claim), on "not found", on an empty body, on a refusal by the safety gate, or on a capture that admits it carried credentials. |
| Metadata credential capture | Cloud machine credentials were retrieved from a genuine metadata endpoint **and** a confirming identity call succeeded with no failure marker at any depth. | Proves structural consistency of the capture. Binding the credential to the confirming call and vouching for the endpoint's provenance is the collection step's responsibility. A retrieved-but-unconfirmed credential is a LEAD. |
| Secret validity | An exposed secret authenticated as a real identity, fingerprint-bound to the confirming call, over a verified connection with no proxy and no redirect, at an endpoint on a fixed approved list. | Claims validity, not where the secret came from. Never inspects or stores the secret's contents. |
| Service-identity impersonation | A short-lived credential was minted **as** a named target identity, and a confirming call at an approved introspection endpoint echoed **that same** identity, fingerprint-bound to the minting. | An echo of a *different* identity does not confirm. A minted-but-unconfirmed credential stays a LEAD. |
| Escalation primitive | The retained configuration unconditionally permits a named escalation manoeuvre that strictly increases reach, shown by an explicit before-and-after comparison. | Does not establish that anyone executed it. Fails closed on every ambiguity. |
| Permission-rule verb grant | See the Kubernetes family above. | Whether it will confirm at all depends on *who* holds the dangerous power (Family 10 sets out the gate). Everything outside that narrow gate stays a LEAD. |

---

## Part 3 — Defensive detection: proving an attack happened from the customer's own logs

The catalogue so far answers "what is wrong with our systems?". A separate set of twelve procedures
answers a different question: **"did someone attack us, and can we prove it?"** These read the
customer's own telemetry — web access logs, network connection logs, authentication logs — and produce
a signed, re-checkable certificate rather than an alert in a dashboard.

Every one of these ships with a **benign twin**: a legitimate look-alike activity that the procedure
must stay silent on. If a benign twin ever triggers a detection, that is treated as a blocking defect
and the change does not ship.

The table below has thirteen rows for twelve procedures, because the scanner-identification procedure
has two distinct modes with two different strengths of claim.

| Detection | Plain meaning | Grade | Benign twin that must stay silent |
|---|---|---|---|
| Port scan | One source contacted at least 15 distinct destination ports in a window — network mapping. | Proven fact | An uptime monitor, which hits one or a handful of fixed ports |
| Forced browsing | One source produced at least 12 distinct "not found" paths in a window — dictionary-driven content discovery. | Proven fact | A well-behaved crawler, which fetches real pages and produces few "not found" results |
| Scanner fingerprint | A client identified itself as a known security scanner in its own request header. | Proven fact | — |
| Scanner path burst | A burst of at least 3 distinct infrastructure- or secret-discovery paths from one source. | LEAD only | Deliberately kept a lead: a path pattern is suggestive; a tool that names itself is proof |
| Content-management enumeration | A burst of at least 5 distinct platform paths from one source — plug-in, theme or user walking. | Proven fact | A normal visitor, who touches two or three such paths for one theme |
| Firewall probing | A client identified as a firewall-fingerprinting tool, or one source throwing at least 3 distinct attack classes to provoke a reaction. | LEAD only | Deliberately kept a lead, because the same pattern is consistent with a genuine multi-vector attacker; the per-class detections below independently produce the proven facts |
| SQL injection structure | A request contains genuine injection structure — a numeric or self-equal always-true condition, a `UNION SELECT`, a timing or error function, or a quote-break-and-comment. | Proven fact | A legitimate filter expression such as `type=novel and year=2024`, the word "select" in prose, or an apostrophe in a surname |
| Cross-site scripting structure | A request contains a real script block, a curated event handler, or a script-carrying link. | Proven fact | Escaped markup, or the words "javascript"/"onload" appearing in prose |
| Path traversal | A request contains a directory-escape sequence (encoded or raw) or a known sensitive absolute path. | Proven fact | A dotted filename such as `report..2024.pdf` |
| Line-break injection | A request contains an encoded or raw carriage-return, line-feed or null character. | Proven fact | The literal text "0a" appearing in a value |
| Command injection | A request contains a shell substitution, or a separator followed by a real program name carrying genuine command structure. | Proven fact | A lone ampersand used as a web-address separator, or a delimited list whose token merely equals a program name |
| Brute force | One account accrued at least 8 authentication failures in a window. | Proven fact | A forgetful user mistyping three or four times |
| Password spray | One source failed against at least 8 distinct accounts, each with at most 2 failures, in a window. | Proven fact | A legitimate login surge, which is many distinct users *succeeding* |

**Honest limits, recorded in the code itself.**

- These detections read logs. They prove that traffic with a certain structure arrived; they do not
  prove the attack succeeded.
- The password-spray detection records an explicit caveat on every result: the available
  authentication log retains the source, the account and the outcome, but **not the attempted
  password**. So the detection proves the *fan-out fingerprint* — one origin, many accounts, shallow
  failures — and not, literally, that the same password was used each time. Confirming that would need
  richer telemetry that is not present. This is stated, not faked.
- Coverage is honest about which planes exist. Two planes are built and working: the network edge
  (reconnaissance and injection over access and connection logs) and authentication telemetry
  (credential attacks over the authentication log). The outbound-traffic, directory-service, cloud and
  user-session planes are explicitly marked in the code as lead-only placeholders — no telemetry is
  ingested for them and no proof is offered.
- A detection becomes a proven fact only when a signed certificate for it re-verifies offline, which
  includes re-running the same procedure over the embedded evidence. If the signing keys are not
  wired in, or a certificate fails to re-verify, the result degrades to a LEAD. It is never silently
  suppressed.

---

## Part 4 — Which claims may be stated as a proven negative

For a national agency the negative claim is often the more valuable one. Knowing a weakness *is* there
tells you to fix it. Being able to show that it is *not* there is what lets a team close an action,
put a recently-patched service back into production, or answer an assurance question with evidence
instead of an assertion.

One boundary belongs at the top of this part rather than the bottom, because it is the boundary most
easily over-read. What the system issues is a signed, coverage-bounded, offline-re-checkable negative:
*over the surface we actually reached, with the tests we actually ran, on this date, this weakness was
not exploitable.* It is evidence a reviewer can check for themselves without trusting the supplier who
produced it. It is **not** a certification, an accreditation, or a statement of compliance with any
scheme, and nothing in the software claims a role in one. What a customer's own assurance or approval
process chooses to do with the evidence is entirely the customer's decision.

The system maintains a formal register of 26 **evidence windows**. (The software's own word for these
is "branches", which is why the term appears in the source and in the register's file name; this
chapter says *window* throughout, because that is what they are.) A window is the specific channel
through which a particular claim may be proved — for example, "we saw this in the response headers" is
a different window from "we saw this in the page text", because the page text may be compressed or
encoded in ways that cannot be fully trusted, and the headers cannot.

The register is not documentation. It is enforced by the running software: a claim arriving through an
unregistered window is a fatal error, and a window that is not marked as capable of a proven negative
**cannot produce one**, regardless of what the test found.

| # | Evidence window | Channel looked through | May state a proven fact | May state a proven negative |
|---:|---|---|:--:|:--:|
| 1 | Open redirect seen in the redirect header | Response headers | Yes | **Yes** |
| 2 | Open redirect seen in page markup | Page body | Yes | No |
| 3 | Open redirect seen in page script | Page body | Yes | No |
| 4 | Cross-origin sharing reflecting a hostile origin with credentials | Response headers | Yes | **Yes** |
| 5 | Host-header injection seen in the redirect header | Response headers | Yes | **Yes** |
| 6 | Host-header injection seen in a link the page emits | Page body | Yes | No |
| 7 | Sign-on redirect address seen in the redirect header | Response headers | Yes | **Yes** |
| 8 | Sign-on redirect address seen in page markup | Page body | Yes | No |
| 9 | Service reachability by connection handshake | Network transport | Yes | **Yes** |
| 10 | Encryption weakness by handshake | Encrypted handshake | Yes | **Yes** |
| 11 | Vulnerable dependency by version-range membership | Supplied document | Yes | No |
| 12 | Kubernetes benchmark control | Supplied document | Yes | No |
| 13 | Kubernetes anonymous role binding | Supplied document | Yes | No |
| 14 | Service mesh declared configuration | Supplied document | Yes | No |
| 15 | Build pipeline workflow construct | Supplied document | Yes | No |
| 16 | Cloud achieved state, from infrastructure-as-code | Supplied document | Yes | No |
| 17 | Cloud permission path, from infrastructure-as-code | Supplied document | Yes | No |
| 18 | Cloud achieved state, from a live capture | Live capture | Yes | No |
| 19 | Cloud cross-account party, from a live capture | Live capture | Yes | No |
| 20 | Cloud permission path, from a live capture | Live capture | Yes | No |
| 21 | Metadata credential capture | Live capture | Yes | No (and not targeted) |
| 22 | Exposed-secret validity | Live capture | Yes | No (and not targeted) |
| 23 | Service-identity impersonation | Live capture | Yes | No (and not targeted) |
| 24 | Kubernetes anonymous privileged binding | Live capture | Yes | No (and not targeted) |
| 25 | Cloud escalation primitive | Live capture | Yes | No (and not targeted) |
| 26 | Kubernetes dangerous permission grant | Live capture | Yes | No (and not targeted) |

**Read this table as follows.** Every one of the 26 windows can produce a proven positive finding.
Only **6** can currently produce a proven negative — and all six read either the response headers, the
network connection itself, or the encrypted handshake, where the channel is complete and unambiguous.
Every window that reads a page's text, a document the operator supplied, or a single live capture may
currently say only "found", "suggested", or "could not tell".

### Why the negative is genuinely harder — and why that is a feature

A positive claim needs one solid observation to settle it: find the weakness once and it is there. A
negative claim is a statement about *every* way the weakness could have shown itself, so it also
requires showing that the channel you were watching through could actually have seen it.

The everyday version of this is a smoke detector that has been silent all year. That silence is good
news only if the battery works. A silent detector with a dead battery produces exactly the same
evidence as a house that never caught fire. Before treating silence as safety, you have to establish
that the alarm was capable of sounding.

The system makes this operational rather than rhetorical. Every observation carries an explicit flag
saying whether it was *conclusive*, and a negative may only be reported as CLEAN when that flag is
set. It is set only when the test genuinely had a channel to look through and reached a decisive
verdict. Three examples of that: the yes/no statistical test ran its rounds and crossed the boundary
that *refutes* the weakness; the timing test took an adequate number of measurements and found no
shift at all; or the test input was actually seen arriving at the place where it would have done harm
and was observed being safely neutralised on the way in.

The flag is deliberately **not** set for the most common case of all: "we sent something and nothing
came back". A page that quietly ignores everything it is sent, a place where the input arrives with no
visible effect, and a genuinely safe page all look identical from the outside. That is the dead
battery. In that case the answer is INCONCLUSIVE, and the system says so.

### What each unproven negative is waiting on

The register requires that any gap between what a window can do today and what it must eventually do
carries a named piece of engineering work. Seventeen of the 26 windows carry such an entry. A gap
without named work fails the automated check, which means a capability can never be quietly abandoned
by rewriting the claim downwards.

Read together, those entries reveal something important: almost every one is a **completeness**
problem, not a detection problem. The system can already find these weaknesses. What it cannot yet do
is prove it has looked *everywhere*.

| Evidence window | What a proven negative additionally requires |
|---|---|
| Open redirect in page markup | The ability to read *every* page reliably, rather than only the ones whose format is unambiguous. Four specific things, explained below the table: a faithful implementation of the published rules for working out which alphabet a page is written in; proper unpackers for the newer ways pages are compressed in transit; the ability to read a page delivered in several compressed pieces; and proof that the page was read to the end rather than cut short. |
| Open redirect in page script | Reading the script text cannot prove absence, because a redirect assembled while the page runs never appears literally in the source. Closing this requires the real-browser path to observe the actual navigation. |
| Vulnerable dependency | Resolving version constraints that are not pinned to an exact number, and recording the advisory snapshot's coverage, so that "no advisory matched" becomes a bounded negative rather than an open one. |
| Kubernetes benchmark | A control-coverage manifest listing the expected checks per node role and benchmark version, checked against what the export actually contains. |
| Kubernetes role bindings | Proof that the export enumerates *every* binding, and that the list of dangerous roles is itself exhaustive, including aggregated and custom roles. |
| Service mesh | Enumerating every namespace and workload, resolving encryption-mode inheritance to an effective mode per workload, and recording the export as complete. |
| Build pipeline | Enumerating every workflow plus every reusable workflow and composite step it calls, resolved transitively. |
| Cloud (both document-derived and live) | Proof that the parse or capture enumerated the resource's *full* policy surface — access policy, access-control list, public-access block, encryption setting and network rules all resolved and cross-linked, with template parameters fully resolved. |

**The first row, unpacked.** It is the most technical entry in the register and also the most
instructive, because it shows how demanding an honest negative is.

A web page does not arrive as plain readable text. It arrives as a stream of bytes, and two things
have to be settled before those bytes become letters. First, which alphabet and encoding the page is
written in — English, Greek, Japanese and emoji are all represented differently, and a page can
declare its choice in several competing places. There is a published specification for resolving that,
including which declaration outranks which. Second, pages are usually compressed for transmission, and
several compression formats are in use; some arrive in several separate pieces that must be joined.

Today the system reads a page confidently when the format is unambiguous, and reports "could not tell"
when it is not. To go further and say "there is definitely no redirect in this page", it would need to
read *every* page reliably. That requires, in the project's own terms: a faithful implementation of
the published encoding rules taken from a reference implementation rather than hand-written — the
project's written rules forbid hand-approximating a specification, precisely because an approximation
looks right until the day it is wrong; proper unpackers for the newer compression formats, at fixed
recorded versions so that anyone re-checking the evidence later gets the same bytes on their own
machine; the ability to join a multi-piece compressed page rather than refusing it; and proof that the
page was read to the end rather than cut short by a size limit. Only when all four hold is a silent
result a *channel-confirmed* negative rather than a shrug.

Three further entries concern **where the system inserted its test inputs** rather than what it
detected: the live re-run currently places test values in the part of a web address after the question
mark, and in the folder-like segments of the address itself. Redirect parameters carried in cookies,
in submitted form fields, or in structured message bodies are **not yet probed**. A redirect reachable
only through those routes is therefore currently unexamined, and is reported as unexamined — never as
clean.

### The six windows whose negative is deliberately not targeted

Six evidence windows (covering five capability areas — the container-platform permission area
contributes two of the six) explicitly record that a proven negative is *not* their
goal, with a written argument. The argument is the same in each case and is worth stating in plain
terms: these are confirmations of an **achieved effect** over a single, scoped capture. Proving the
*absence* of a capturable credential, a valid secret, an impersonation path, a dangerous binding, or
an escalation path is a fundamentally different capability — it requires an enumeration of the whole
environment with its own completeness proof. That work belongs to the document-reading posture windows,
which do
target a proven negative. The negative is therefore routed elsewhere, not abandoned.

### The three negative artefacts the system does ship

Despite everything above, the system does issue three signed documents that carry a negative claim.
They are summarised here and then explained one at a time, because each one's honest boundary needs
more than a table cell.

| Artefact | The claim it carries, in one line |
|---|---|
| **Coverage certificate** | "Here is exactly what we tested, and where a test actually reached a decision." |
| **Posture certificate** | "For each thing we tested, here is closed, open, or unproven — and you can check it yourself, offline." |
| **Remediation certificate** | "The attack that provably worked is now provably dead." |

#### The coverage certificate — what was actually tested

For each combination of surface, input and weakness type that the assessment reached, this records
whether an applicable test actually ran and reached a decision. That is what turns a quiet area of a
report from "we did not mention it" into "we tested it and it came back clean". The document is
signed, and the fingerprint used to check the signature is published through a separate channel, so a
reader does not have to trust the same source for both the claim and the means of checking it.

Its limiting statement is written *into the signed content itself*, in the same words every time, so
it cannot be dropped when the document is quoted. It certifies coverage of the surfaces the assessment
**reached**. It is expressly not proof that the whole application was found. The certificate also
carries its own limits — how many pages it was allowed to visit, how deep it was allowed to go, and
whether it ran out of pages to visit or ran out of budget — so nobody can mistake "everything we
reached" for "everything there is".

#### The posture certificate — a certificate of non-exploitability

This is the strongest negative document the system issues. For each combination of surface, input and
weakness type it states one of three words: closed, open, or unproven. It is bound to an
owner-signed statement of what the target actually is, and it carries inside its own signed content
the figure it was measured against — the number of things examined, so a percentage cannot be quoted
without its base.

It supports two levels of checking. At the first, an outside party verifies the signature, the
separately published fingerprint, and the bindings, entirely offline, with none of this software
installed. At the second and stronger level, the certificate additionally contains, for every clean
result, the decision rule that was applied and the evidence it was applied to — so an independent
checker can **work the verdict out again for itself** rather than taking it on trust.

Three boundaries are recorded honestly. "Closed" means not exploitable *by this family of tests, over
the surface actually reached, as of the stated freshness date* — it never means "secure against
everything". A structural rule refuses to issue a "closed" that cannot name a conclusive test behind
it, and "unproven" is never quietly counted as "closed". And even at the stronger level, the honest
bound is stated: the retained values were still supplied by the producer of the certificate, so
re-deriving the verdict proves the verdict follows correctly from that evidence. It does not, by
itself, prove that the evidence faithfully reflects the live target.

#### The remediation certificate — proof that a fix worked

The claim is: the attack that provably worked before now provably does not. The original test is
re-run over freshly captured evidence from the repaired system and goes silent, and the result is
cross-referenced to the original certificate that proved the problem, so the two cannot be separated.

Four outcomes exist — fixed, still vulnerable, inconclusive, and refused — and **all four are signed**.
That matters more than it sounds: because an inconclusive result is signed too, nobody can quietly
delete the reason and present the silence as success.

Silence only counts as a fix when it is *controlled*, in the laboratory sense. A deliberate positive
control must still fire, proving the test equipment is alive and would have detected the problem if it
were still there. The target must have genuinely answered, measured only on parts of the response the
target itself produced and never on values the tool supplied. And the check repeats according to a
policy set for that class of weakness.

The most important honesty measure here is the approved list. Only **13** of the test types are
accepted as ones where silence is a sound negative. Every other type is excluded, each with a written
reason: timing tests, credential stuffing, prompt injection, system-prompt disclosure, memory-safety
crash markers, version-range membership, permission paths, all of the document-reading posture tests,
the sign-on forgery tests, automated access, service reachability, anonymous exposure and encryption
weakness. Race conditions and request-smuggling are excluded specifically because they are not
reliably reproducible, so their silence proves nothing. A weakness type the list does not recognise
fails closed and is never certified as fixed.

---

## Part 5 — What is fully working today, what is built but not yet fired in anger

This section exists because of the project's own written rule: a capability may never be abandoned by
quietly narrowing the claim, and equally, a claim may never run ahead of what has actually been done.
An agency reading this should be able to tell the two apart at a glance.

| Capability | Honest status |
|---|---|
| The core 15 tests against a live web target | **Fully working end to end.** The system stands up a real, deliberately vulnerable application on the local machine and confirms findings against it. Pointed at a safely written twin of the same application, it correctly returns nothing — a shipped negative control demonstrating the confirming authority does not simply rubber-stamp. |
| Service reachability, encryption weakness, version-range membership and the web achieved-state windows | **Working against real captures**, and the first two are among the six windows that may also state a proven negative. |
| Cloud metadata credential capture | **Built and proven offline. Real-network live fire is deliberately deferred**, pending an operator-provisioned laboratory credential. The collection step, the evidence window, the verdict route, the certificate issuance and the world-model projection are all built and proven against fixtures. In the project's own words: *there is no live proven fact yet.* |
| Exposed-secret validity | Same position: producer, verdict and certificate wiring **complete and proven offline**; live fire deferred pending an operator-provisioned credential. |
| Cloud service-identity impersonation | Same position: **offline-wired, live fire deferred** pending operator-provisioned cloud credentials. |
| Kubernetes permission tests (both tiers) | **No longer deferred: proven against a real Kubernetes cluster.** A repository script stands up a genuine single-node cluster (k3s 1.31.5, in a container on the machine's own internal address) that the system creates, owns and destroys; plants dangerous and benign access rules; captures what the real Kubernetes interface returns; and adjudicates those bytes through the production path. The anonymous-caller-bound-to-administrator case is confirmed and its certificate re-verifies offline; the benign cases — including the namespace default identity bound to the built-in `admin` role, whose real rules *do* grant secret reads — correctly stay leads. The script asserts every expectation and exits non-zero on any deviation, and a third party can re-run it. **Not covered by that run:** a scope-gated *enumeration* capability that discovers bindings across a cluster (the script reads the objects it planted, by name), and a managed provider's control plane (EKS, GKE, AKS). |
| Cloud escalation primitive | Pure offline re-derivation over the operator's own retained policy documents. Live fire is **deliberately not part of this capability at all** — a defensive verification test never executes the escalation it describes. |
| The cryptographic escalation of the sign-on assertion test | **Dormant unless** the operator supplies trusted identity-provider certificates *and* the required library is installed. Checking the signature mathematics itself, which requires reproducing the document-tidying step described in Family 6, is explicitly out of scope. |
| Offensively testing a customer's own AI feature (Family 15) | **Built and proven by its own tests; never yet run for real here.** The category table, the routing that keeps an AI judge's opinion from ever becoming a fact, the boundary that runs the outside tool as a separate program, and the fail-closed behaviour are all in place. The four AI red-teaming tools themselves are **absent from this environment and could not be installed, because the machine has no route to the internet.** No proven finding has been produced from them here. Live use is deferred until an operator provisions the tools. |
| The relay needed to confirm invisible weaknesses against a **remote** target | **Built, with its own command to run it, and gated**: the engagement runner refuses a relay whose address is not on the authorisation document. Standing one up is the operator's action, on a host they own. Without it, the four callback-based checks are skipped against a remote target — and reported as skipped, never as clean. |
| The claim-checking layer that re-runs every proof a claim cites | **Built and in real use, but not yet the single checkpoint every claim crosses.** It is called at genuine points in the running system: when findings are written into the system's internal map of the target, when a report is generated, when the defensive side admits a result, and when the reviewing components check an agent's work. What it is **not**, today, is one universal gate through which every claim in the system must pass — the internal map's own admission check reaches the same conclusion by a shared route rather than by calling this layer. It can only ever take a claim *down*; it can never promote one the confirming test refused. A note for reviewers reading the source alongside this briefing: the module's own opening comment still describes it as having no callers yet, and that comment is out of date — the callers exist. |
| Staying logged in while testing an application behind a login | **Built and working inside the testing engine**: it holds the session, notices when it has been dropped, logs in again and repeats the request. The honest gap is not in the capability but in how an operator reaches it — in the version read for this briefing there is no field for a target application's username and password on the assessment wizard or on the command that launches an engagement, so it is configured in the engine directly. |
| The two measurements that are not among the 85 — session-token predictability and exposure to future quantum decryption | **Built, deterministic and reported.** Neither is judged by one of the 38 decision procedures, so neither produces a proven finding. Both are reported as leads with their own stated boundaries, which are set out in families 3 and 8. This is a deliberate classification, not an oversight. |
| The build-and-release safeguards on the system's own supply chain | **Delivered and merged into the main line of the repository**, on the day this chapter was written: fingerprinted dependency locks proven to install under fingerprint checking, container images pinned by content rather than by a movable label, an ingredients list per environment, and a vulnerability gate that blocks on CRITICAL and has a negative control proving it can fail. Set out in full in Family 11. This is a statement about how the system is built, not a test performed against a customer. |
| The graph database backend | A real, reviewable client exists behind the same interface, but the database driver and a running service are **both absent in this environment**. Attempting to use a live store raises a not-implemented error, and the equivalence test is behind a loud skip. |
| The path from an AI model's suggestion to a proven fact | Issuing a proven fact requires reproducing the finding from raw output captured by the execution layer. Until that live re-drive lands, this route yields **LEADs only** — which the code identifies as the correct fail-closed disposition. |

### The rule that keeps an AI model out of the proof

Because AI models are involved in parts of the system, the boundary deserves stating on its own.

- The model **proposes**; the deterministic test **confirms**. Those are different components.
- Issuing a fact requires three conditions together: a test fired at 0.70 confidence or above, the
  weakness type is one of the recognised 85, and the evidence's recorded origin is either "reproduced"
  or "live re-drive". The default origin for anything an AI model touched is "llm", and that is
  **demoted to a LEAD even when the test fires** — because evidence an AI model shaped is an
  AI-influenced route to a fact, and the system closes that route.
- Output from an interactive terminal or agent session is advisory only and never enters the
  confirming pipeline.
- A claim produced in a reasoning-only mode may stand only on grounds that can actually be re-executed
  — never on its own reasoning.

---

## Part 6 — The attack library behind the catalogue

The 85 types describe *what* can be found. Three further inventories describe the concrete attacks the
system actually sends: a small set of checks that always run, a large library of individual attack
definitions held as data, and a separate engine for sending *many* variations of one attack.

**Eleven seed checks always run.** These are the default active tests on any web assessment: blind
yes/no database injection, reflected cross-site scripting, two forms of template-injection arithmetic,
path traversal, error-based injection, open redirect, and four callback-based checks (server-side
request forgery, XML external entity, command execution, and unsafe object reconstruction). The four
callback checks run **only** when the system has a receiver available to hear the callback; without
one they are skipped, never guessed.

That last sentence hides an operational prerequisite that a buyer needs to know about, so it is
spelled out here. Those four checks confirm weaknesses that produce no visible result on the page. The
only proof available is that the customer's server reached out and contacted a machine the system
controls. The receiver that hears such a call is, by default, listening only on the testing machine
itself. That is sufficient when the target application is running on the same machine, and it is how
the local demonstrations work. Against a **remote** target it is not: a remote server cannot call back
to a listener that only accepts connections from its own machine.

For remote work the operator must therefore stand up a small relay of their own — a listening post on a
host they own, which they have written into the engagement's authorisation document. The system ships
one, with its own command to run it, and it is deliberately a relay you host rather than a service you
rent from a third party. It records every incoming contact against the one-off token that identifies
the test, and hands those records back over an authenticated connection, so no outsider can read the
operator's results. The engagement runner refuses to use a relay whose address is not on the
authorisation document's approved list. Its stated scope is contacts that arrive as ordinary web
requests; a weakness that only ever produces a name-lookup and never a web request would need a
name-service relay, which is documented as a future extension rather than silently implied.

The consequence, stated plainly: **against a remote target, with no relay running, those four checks
are skipped.** They are reported as skipped and never as clean, but an operator who does not know this
could run a remote assessment, see no server-side request forgery and no remote code execution
findings, and draw the wrong conclusion.

**A further 172 attack definitions** are held as structured data files rather than program code, which
means the library can grow without changing the engine. Their distribution across weakness types is:

| Weakness type | Number of attack definitions |
|---|---:|
| Blind yes/no database injection | 21 |
| Exposed files and endpoints | 20 |
| Cross-site scripting | 18 |
| Command injection | 17 |
| Unsafe object reconstruction | 14 |
| Server-side request forgery | 13 |
| Template injection | 11 |
| Time-based database injection | 11 |
| Blind XML external entity | 10 |
| Error-based database injection | 8 |
| Path traversal | 7 |
| NoSQL injection | 5 |
| Database injection (generic) | 3 |
| Local file inclusion | 2 |
| Authentication bypass | 2 |
| Remote code execution | 2 |
| Time-based command injection | 2 |
| Expression-language injection | 1 |
| Sensitive data exposure | 1 |
| Directory-service injection | 1 |
| Time-based (generic) | 1 |
| XML query injection | 1 |
| XML external entity | 1 |
| **Total** | **172** |

Within those families the coverage includes database-engine-specific variants for five major database
products, eleven distinct page-template engines, both Windows and Unix command variants, obfuscated
forms of the widely exploited Java logging vulnerability, and twenty framework-exposure paths covering
source-control directories, environment files, diagnostic and management endpoints, search and
container registries, content-management user listings, interface specification documents, and
application log and route files.

**The third inventory: many variations of one attack, triaged automatically.** The checks above each
send a *fixed* test input for a given weakness. There is a second axis to any real assessment: sending
*many* inputs into the same place and looking for the one response that stands out. Guessing at
identifiers, sweeping through record numbers, trying a long list of candidate values, probing how a
field behaves at unusual lengths — all of these are that shape of work.

The system contains a dedicated engine for it, and its design is worth a paragraph because of how the
last step is handled. It has three parts.

- **The vocabulary of input sets.** A fixed list of values; values streamed from a file; a run of
  sequential numbers, for sweeping through record identifiers; every combination over a set of
  characters within a length range; the *same* value repeated many times unchanged, which is what a
  race-condition test needs; upper- and lower-case variations, for probing filters; growing blocks of
  a repeated character, for probing length handling; a single bit of a value flipped at a time, for
  probing how signed or encrypted fields are validated; and a range of dates. Each one is produced
  lazily and in a fixed order, so a very large run costs nothing up front and repeats identically.
- **Marking where the values go, and in what combination.** The operator's chosen positions in a
  request are marked, and four standard patterns decide how inputs are placed into them: one position
  at a time with the others left alone; the same value into every marked position at once; one list
  per position stepped through in lockstep, for genuinely paired values such as an account number and
  its matching token; or every combination of every list, which is the pattern a username-and-password
  sweep needs. There is also a processing pipeline that can transform each value before it is sent —
  adding a computed fingerprint, adding an encoding layer, or dropping values that match a rule.
- **Finding the needle, without a human.** This is the notable part. The standard commercial equivalent
  of this engine presents the tester with a table of thousands of rows and expects them to spot the
  interesting one by sorting columns. Here that step is automated: the whole population of responses is
  baselined, and the rows that stand out are flagged — a response code held by only a small minority
  (the one success among hundreds of refusals), a response whose length sits far from the typical
  centre (the one that returned a record among hundreds that returned nothing), or a row matching a
  phrase the operator asked to watch for. The statistics used are the kind that are not thrown off by a
  few extreme rows. The same rows in always produce the same flagged rows out.

Two honest notes. Every request this engine sends goes through the same permission, scope, kill-switch
and pacing gate as every other request; and the run is capped by a maximum number of requests, so an
automatic sweep cannot run away with itself. And, in the version read for this briefing, this engine is
a component driven by the testing engine rather than a separate command or a screen an operator clicks:
it is not one of the system's own listed commands, and it does not appear as one of the interface
screens. It also does not decide anything. Flagging an unusual response is a *lead*; whether it becomes
a proven finding is decided by the same automatic decision procedures as everything else in this
chapter.

**Which capabilities are switched off by default.** A default assessment is deliberately conservative.
The following require the operator to turn them on, and several require the operator to supply
information the system will not invent:

| Capability | What it needs |
|---|---|
| Single sign-on checks | Opt-in; runs against the operator's own service only |
| GraphQL resource-abuse checks | Opt-in |
| Access-control cross-checking | Opt-in; requires two genuine identities and a named reference to swap |
| Business-logic workflow abuse | Opt-in; requires the operator to describe the intended workflow |
| Concurrency and race testing | Opt-in |
| Request smuggling | Opt-in |
| Live two-way connection testing | Opt-in |
| Browser-based cross-site scripting and single-page-application crawling | Requires a real headless browser — an ordinary web browser run with no window on screen, driven by the software instead of by a person, so that pages which build themselves after loading can be seen as a user would see them |
| The four callback-based checks, against a **remote** target | An out-of-band relay running on a host the operator owns and has listed in the authorisation document. Without one they are skipped and reported as skipped. Against a target on the same machine, no relay is needed |
| The access-control and business-logic families, on an application behind a login | A working login for the target application, supplied by the operator, plus a second identity for the cross-checks. In the version read for this briefing this is configured in the engine rather than typed into the assessment wizard |
| Testing a customer's own AI feature (Family 15) | The chosen AI red-teaming tool must be installed on the machine. None of the four is present in the environment this briefing was written from |
| The advanced discovery arsenal | Opt-in, and its output is kept **strictly separate** from confirmed findings — discovered paths, references found in page scripts and capability observations are recorded as context, not as findings |

---

## Part 7 — What this catalogue does not cover

An exhaustive list is only honest if it also says where it stops.

- **Physical, personnel and process security are out of scope.** This catalogue is entirely about
  technical weaknesses observable through software.
- **What happens *after* a break-in is refused by design, not merely unbuilt.** A traditional
  penetration test continues after the first success: moving sideways to other machines, installing
  something that survives a reboot, setting up a channel to control the compromised machine later.
  None of that is in this catalogue, and it is not an omission. The relevant source file lists the
  excluded items and the instruction beside them is "refuse, never build": no hiding from the
  customer's own defences, no remote-control channels, no implants or persistence, no ready-made
  full-chain weapons, no credential-attack suites, no rotating identities or chains of relays to
  disguise the source, and no unattended action against any live or third-party machine. The most
  advanced thing this part of the system will do is re-run the exact proof that a confirmed finding
  already produced, on request, with a human approving that specific action — and if the proof no
  longer reproduces, it reports a refusal rather than asserting an impact it cannot demonstrate. An
  agency should read the catalogue as "everything we will find and prove", not as "everything an
  attacker would do next".
- **Nothing here proves an organisation is secure.** Every proven negative is bounded by the surface
  actually reached, the tests actually run, and the time window in which they ran. The certificates
  say so in their own signed content.
- **A finding is a bounded observation, not a permanent property.** A system that was clean yesterday
  may be vulnerable today, and the certificates carry their freshness bounds for exactly this reason.
- **Several capabilities are built and proven offline but have not yet been exercised against live
  third-party infrastructure.** These are named individually in Part 5. They are real, working,
  reviewable code with test-proven behaviour, and they are not the same thing as a field-proven
  deployment. Anyone representing them as field-proven would be misrepresenting them.
- **The system reports "could not tell" often, and that is intentional.** An inconclusive result is
  the honest answer whenever the observation channel was not demonstrably capable of seeing the
  weakness. It is never rounded up into good news.
- **The list will grow.** Adding a new weakness type or a new test is a normal engineering activity.
  The structural safeguard is that adding one cannot change what an existing assessment does, cannot
  widen what an unrecognised weakness type may be confirmed by, and cannot produce a proven negative
  unless its evidence window is registered as capable of one.

---

## Appendix A — The full vocabulary mapping

This appendix exists for completeness and for anyone reconciling a VIGIL report against another
supplier's report. **A general reader does not need it.**

The left-hand column is the master name the system files a weakness under — the software's own
spelling, reproduced exactly, which is why it is written in lower case with underscores. The middle
column says what it means. The right-hand column lists the other spellings the system accepts and
converts to that master name. There are 57 master names with alternatives, 190 alternatives in total,
and every alternative resolves to a master name; none is left pointing at nothing. The remaining 28
master names have no registered alternatives and appear only under their own name in Part 1.

| Master name | What it means in one line | Other spellings the system accepts |
|---|---|---|
| `auth_bypass` | Logging in can be skipped entirely. | authentication_bypass |
| `authorization` | A permission check failed, in general. | authz |
| `automated_access` | A machine, not a person, was browsing the site. | automated_scraping, bot_access, honeypot_fetch, honeypot_hit |
| `bfla` | An ordinary user can call an administrator-only function. | broken_function_level_authorization |
| `bola` | A machine interface hands over another customer's record. | broken_object_level_authorization |
| `boolean_sqli` | Database contents read out one yes/no question at a time. | blind_sqli, boolean_based_sqli |
| `broken_access_control` | A permission check is missing or ineffective. | access_control |
| `business_logic` | A business process is performed out of order, repeated, or with tampered values. | business_logic_abuse, insufficient_workflow_validation, parameter_tampering, state_machine_abuse, workflow_abuse, workflow_violation |
| `cloud_misconfiguration` | A cloud setting is explicitly unsafe — public, unencrypted, or open to anyone. | anonymous_grant, cloud_misconfig, cloud_posture, cloud_security_misconfiguration, cspm_finding, cspm_misconfiguration, encryption_at_rest_disabled, public_bucket, public_s3_bucket, public_storage, unencrypted_at_rest, wildcard_principal |
| `command_injection` | Attacker text is run as a command on the server. | cmdi, os_command_injection |
| `credential_stuffing` | Stolen password lists used to break into many accounts at once. | account_takeover, ato, cred_stuffing, credential_stuffing_ato, credential_stuffing_attack, password_spraying |
| `deserialization` | The server rebuilds attacker-supplied data and runs attacker logic doing so. | insecure_deserialization |
| `excessive_privilege` | An account holds far more access than it needs. | excessive_permissions, excessive_privileges, over_permissioned, over_privileged, overprivileged |
| `exposure` | Something internal is reachable that should not be. | framework_exposure, information_disclosure |
| `gcp_sa_impersonation` | One cloud identity can act as another. | gcp_impersonation, gcp_service_account_impersonation, iam_service_account_impersonation, iam_serviceaccount_impersonation, sa_impersonation, service_account_impersonation |
| `graphql_alias_overloading` | The same costly request repeated many times inside one message. | graphql_alias, graphql_alias_abuse, graphql_aliasing |
| `graphql_batching` | Many operations bundled into one message and all executed. | graphql_batch, graphql_batching_abuse, graphql_query_batching |
| `graphql_cost` | Query cost or complexity abuse in general. | graphql_complexity, graphql_query_cost, graphql_resource_exhaustion |
| `graphql_depth_limit` | A deeply nested query accepted with no depth guard. | graphql_deeply_nested_query, graphql_depth, graphql_query_depth, graphql_unbounded_depth |
| `iam_escalation_primitive` | A cloud permission that lets an account give itself strictly more power. | achieved_iam_escalation, iam_escalation, iam_privilege_escalation_primitive |
| `iam_privilege_escalation` | A cloud identity can reach a more powerful position. | iam_privesc |
| `idor` | Change the record number in the address, see someone else's record. | insecure_direct_object_reference |
| `imds_credential_capture` | A server's own cloud credentials were taken and proven to work. | cloud_metadata_credential_capture, imds_capture, imds_credential_theft, imds_ssrf, instance_metadata_credential_capture, instance_metadata_credential_theft, metadata_credential_capture, ssrf_to_imds |
| `jwt_forgeable` | A sign-on token can be forged by anyone holding it. | jwt_alg_none, jwt_algorithm_confusion, jwt_forgery, jwt_key_confusion, jwt_none_alg, jwt_signature_forgery, jwt_structural_forgery, jwt_weak_key, jwt_weak_secret, rs256_hs256_confusion, sso_assertion_forgery |
| `k8s_misconfiguration` | A container-platform control-plane setting is dangerous. | cis_k8s_fail, insecure_k8s_setting, k8s_insecure_setting, k8s_posture, kube_bench_fail, kubernetes_misconfiguration |
| `k8s_rbac_privilege_grant` | A container-platform role really does grant dangerous powers. | default_serviceaccount_privileged_binding, k8s_dangerous_rbac_grant, k8s_rbac_dangerous_verb_grant, k8s_rbac_verb_grant, rbac_dangerous_verb_grant |
| `k8s_workload_misconfiguration` | An anonymous caller is attached to a dangerous administrative role. | anonymous_cluster_admin, anonymous_rbac_binding, k8s_rbac_misconfiguration, k8s_workload_posture, rbac_anonymous_privileged_binding |
| `ldap_injection` | Injection into a corporate directory query. | ldap, ldapi |
| `lfi` | The application is tricked into loading a local file as part of itself. | file_read, local_file_inclusion |
| `mesh_misconfiguration` | The internal service-to-service layer declares a permissive state. | authorization_policy_allow_all, istio_misconfiguration, linkerd_misconfiguration, mesh_misconfig, mesh_posture, mesh_unauthenticated_inbound, peer_authentication_permissive, permissive_mtls, service_mesh_misconfiguration |
| `nosql_injection_attempt` | A request provably smuggled a database operator into a plain value. | mongo_injection_attempt, mongodb_injection_attempt, mongodb_operator_injection, nosql_breakout, nosql_operator_injection, nosqli_attempt |
| `nosqli` | Injection against a modern document database. | no_sqli, nosql_injection |
| `oidc_idtoken_forgery` | A forged identity token was accepted by the login system. | id_token_forgery, idtoken_forgery, oidc_idtoken_acceptance |
| `oidc_redirect_uri` | The login system will send a fresh credential to an attacker's address. | oidc_open_redirect, redirect_uri_validation |
| `path_traversal` | Escaping the intended folder to read files never meant to be served. | directory_traversal |
| `privilege_escalation` | A low-privilege actor reaches a state requiring higher privilege. | privesc |
| `privilege_path` | A real chain of permission grants reaching a sensitive resource. | iam_path, iam_privilege_path, privilege_escalation_path |
| `prompt_injection` | Outsider text changed the behaviour of an AI feature. | indirect_prompt_injection, jailbreak, llm_prompt_injection |
| `rce` | The attacker runs their own code on the customer's server. | remote_code_execution |
| `saml_assertion_tampering` | An altered single sign-on login document was accepted. | saml_assertion_forgery, saml_signature_bypass, saml_tampering |
| `saml_signature_wrapping` | A shuffled signature no longer covers the identity being used, and was accepted. | saml_xsw, signature_wrapping, xml_signature_wrapping, xsw |
| `saml_structural_forgery` | A captured sign-on document is forgeable from its own structure. | saml_forgeable, saml_forgery, saml_offline_forgery, saml_reference_mismatch, saml_structural_forgeability, saml_unsigned_assertion |
| `secret_credential_validity` | An exposed key was proven to be still working. | exposed_secret_validity, leaked_credential_validity, secret_validity, valid_exposed_secret |
| `security_misconfiguration` | An unsafe setting reachable over the application surface. | misconfiguration |
| `sensitive_exposure` | Genuinely sensitive data is exposed. | sensitive_data_exposure |
| `service_reachable` | A network service is open and answering. | open_port, port_open, reachable, service_reachability |
| `sqli` | Attacker text is run as a database query. | sql_injection |
| `ssrf` | The customer's server is made to fetch an address of the attacker's choosing. | server_side_request_forgery |
| `ssti` | The page-building engine evaluates the attacker's expression. | server_side_template_injection |
| `system_prompt_disclosure` | An AI feature leaked its own confidential instructions. | canary_disclosure, system_prompt_exfiltration, system_prompt_leak |
| `time_based_command_injection` | Blind command injection, confirmed by making the server pause. | time_based_cmdi, time_based_rce |
| `time_based_sqli` | Blind database injection, confirmed by making the server pause. | blind_time_sqli, time_based_blind_sqli, time_sqli |
| `vulnerable_dependency` | A pinned third-party component version falls inside a published advisory. | cve, known_vulnerable_dependency, outdated_dependency, sca, vulnerable_component |
| `weak_tls` | The encrypted connection negotiated an obsolete protocol or weak cipher. | deprecated_tls, ssl_weakness, tls_weakness, weak_cipher, weak_ssl |
| `xpath_injection` | Injection into a query over an XML document. | xpath, xpath_injection_blind, xpathi |
| `xss` | The attacker's script runs inside another user's browser session. | cross_site_scripting, reflected_xss, stored_xss |
| `xxe` | A malicious XML document makes the server read files or make connections. | xml_external_entity |

Two of these entries carry abbreviations that are worth restating: **IAM** is identity and access
management, the part of a cloud account that decides who may do what, and **RBAC** is role-based
access control, the equivalent on a container platform.
