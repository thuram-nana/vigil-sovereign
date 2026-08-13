# The Tools It Uses, And What You Need To Run It

This chapter has two halves.

The first half answers a question every technical evaluator asks: *what does this
system actually run?* Security testing has a well-known public toolbox — free
programs that scan networks, probe web sites, and look for known weaknesses. This
system can drive a number of those programs. The important part is not the list.
The important part is the rule the system applies to everything those programs
say: **their output is a tip, never a conclusion.** Nothing another program
reports becomes a proven finding until the system has gone back to the target,
collected its own evidence, and reached the same conclusion by its own means.

The second half is practical. If your organisation decided today to run an
operation with this system, what would you need? What **licence** must you hold —
and there is a point here that concerns public-sector readers directly, so it is
stated first rather than buried. Which accounts and keys are genuinely required
and which are optional? What machine does it run on? What network access does it
need? What does an operator do on their first day? How do you back it up, restore
it, upgrade it, and remove it? What safeguards sit around the way the software
itself is built and released? And, because it matters to any government buyer:
**what information leaves your building, and what never does?**

Everything below is drawn from the system's own source code and its own
documentation. Where a capability is built and tested but has not yet been run
against a live outside system, that is stated plainly rather than glossed over.

---

## Part One — The Tools It Uses

### 1.1 The single rule that governs every tool

The system divides everything it knows into two categories, and it uses two
plain words for them.

- A **lead** is *anything anyone said*. A scanner said a port was open. A
  language model suggested a page looked suspicious. A third-party tool printed
  a warning. All of that is a lead. A lead is useful for deciding where to look
  next. It is never presented as a proven problem.
- A **fact** is *a conclusion the system reached itself*, using a fixed,
  automatic test, over evidence the system collected and kept. That evidence is
  stored with the conclusion, and anyone can re-run the same test over the same
  stored evidence later, on a different computer, with no network and without
  trusting the system at all.

The gap between a lead and a fact is closed only by **re-doing the work**. It is
never closed by believing a message.

A useful comparison is a medical one. A colleague telling you a patient "looks
anaemic" is a lead. It is a good reason to order a blood test. It is not a
diagnosis. The blood test — a defined procedure, run on a retained sample, with
the sample kept so another laboratory can repeat it — is the fact. This system
is built so that no amount of confident-sounding output from a scanner can skip
the blood test.

Two consequences follow, and both are unusual:

1. **A tool's own claim is discarded even when the tool is probably right.** If a
   scanner reports an open port, the system opens its own connection to that
   port, keeps the record of what happened, and lets its own fixed test judge
   that record. If its own attempt does not reproduce the result, the scanner's
   claim stays a lead forever. It does not become a "probable" finding.
2. **The number of tools is not the measure of the system.** The measure is how
   many tools are allowed to produce a proven fact, and that number is
   deliberately tiny.

### 1.2 The catalogue: what each tool is permitted to claim

The system keeps a written catalogue of outside tools. It records, per tool, the
one thing that matters: **may this tool's output ever become a proven fact, or
may it only suggest where to look?**

The catalogue is derived from a large published collection of 79 security tools.
The catalogue itself currently carries **33 tools**. Of those 33:

- **2 tools may contribute to a proven fact**, and even then the tool is not the
  authority — the system re-does the measurement itself.
- **14 tools are "lead only"** — allowed to point, never to conclude.
- **17 tools are excluded entirely** — they may not even be proposed, because
  they are attack, password-cracking, or persistence tools rather than
  measurement tools.

Here is the complete catalogue, with a plain-English meaning for each entry.

**Tools that may contribute to a proven fact (2)**

| Tool | What it does, in plain terms | How the system treats it |
|---|---|---|
| `nmap` | Knocks on a machine's network "doors" to see which are open and what is listening behind them. | The system re-opens the connection itself with its own gated attempt and judges its own record. A door the system cannot re-open itself becomes a lead, never a fact. |
| `sslscan` | Checks what encryption settings a server will accept when a browser connects. | The system performs its own encryption handshake and judges the settings it actually negotiated. |

**Tools allowed only to suggest where to look (14)**

| Tool | What it does, in plain terms |
|---|---|
| `httpx` | Quickly checks which web addresses respond, and what software appears to be behind them. |
| `katana` | Crawls a web site to discover its pages and links. |
| `subfinder` | Finds sub-addresses of a domain (for example `mail.example.com`) from public records. |
| `nuclei` | Runs a large library of community-written checks for known weaknesses. |
| `gobuster` | Guesses hidden folder and file names on a web server. |
| `trivy` | Reads a project's list of software components and flags ones with published vulnerabilities. |
| `grype` | Does the same job as `trivy`, from a different vendor. |
| `checkov` | Reviews infrastructure configuration files for unsafe settings. |
| `prowler` | Reviews a cloud account's settings against a security benchmark. |
| `kube-bench` | Reviews a Kubernetes cluster's settings against a security benchmark. |
| `gdb` | A programmer's debugger, used to inspect a crashing program. |
| `scout-suite` | Another cloud-account configuration reviewer. |
| `terrascan` | Another infrastructure-configuration reviewer. |
| `kube-hunter` | Probes a Kubernetes cluster for known weaknesses. |

**Tools excluded entirely (17)** — never proposed, never a source of a fact.

| Tool | What it does, in plain terms | Why excluded |
|---|---|---|
| `sqlmap` | Automates attacking and extracting data from databases through a web site. | Attack and data-extraction tool. The system proves database-injection weaknesses with its own controlled test instead. |
| `xsser` | Automates injecting hostile script into web pages. | Attack tool. |
| `metasploit` | The best-known general exploitation framework. | Attack tool. |
| `pacu` | Cloud-account exploitation framework. | Attack tool. |
| `pwntools` | A toolkit for writing memory-corruption exploits. | Attack tool. |
| `angr` | Automated program analysis used to build exploits. | Attack tool. |
| `ropgadget` | Finds reusable fragments of a program used in exploit construction. | Attack tool. |
| `ropper` | The same job as `ropgadget`. | Attack tool. |
| `one-gadget` | Finds a single instruction sequence that grants a command shell. | Attack tool. |
| `libc-database` | Identifies system library versions to build a matching exploit. | Attack tool. |
| `pwninit` | Prepares an exploit-development workspace. | Attack tool. |
| `hashpump` | Forges certain kinds of authentication tags. | Attack tool. |
| `hydra` | Tries password after password against a login page. | Credential attack. |
| `netexec` | Sprays credentials across a corporate network. | Credential attack. |
| `responder` | Impersonates network services to capture passwords. | Credential attack and impersonation. |
| `john` | Cracks captured password hashes. | Credential attack; marked as requiring exceptional authorisation. |
| `hashcat` | The same job as `john`, using graphics hardware. | Credential attack; marked as requiring exceptional authorisation. |

**Two things the system measures entirely by itself, with no tool as authority**

There are two further categories of finding where the outside tool is only ever a
signpost:

- **Out-of-date software components.** Tools like `trivy` and `grype` will tell
  you that a project uses a vulnerable library. The system does not accept that.
  It reads the project's own component list itself, compares it against a fixed,
  stored snapshot of the public vulnerability database, and reaches its own
  conclusion. The tools stay "lead only" by design.
- **What a web server actually did.** Tools like `httpx` will report that a page
  redirects somewhere unexpected, or that it shares data with untrusted sites.
  The system does not accept that either. It sends its own request, with
  redirects deliberately switched off so it sees the raw response, keeps that
  response, and judges it with its own fixed test.

The catalogue also enforces structural rules automatically. An excluded tool can
never be marked fact-capable. A fact-capable tool must name the specific test
that judges its output. And there is a hard-coded backstop list of known attack
and password-cracking programs, so a catalogue entry cannot escape exclusion by
relabelling itself as something harmless.

The catalogue's checker is honest about its own limit, which is worth noting
because it is the sort of thing most products would leave unsaid: the check
verifies the *shape* of each entry, not that the named test really exists. That
second question is answered separately, by the acceptance battery described later
in this chapter and by a test that pins the list of fact-capable tools so it
cannot quietly grow.

**An apparent contradiction, explained rather than hidden.** Two tools —
`sqlmap` and `hydra` — appear both in the excluded list above and in the roster
of programs the system will launch, described in the next section. That is not an
inconsistency; they are two different statements about two different things.

- The engine *can* be instructed to run them. Both are classified as destructive
  and are gated harder than anything else in the system.
- Their **output can never become a proven finding**. The catalogue's note on the
  `sqlmap` entry says it directly: the system confirms database-injection
  weaknesses with its own controlled re-test and its own fixed judgement,
  "never sqlmap."

In other words, running a tool and believing a tool are separate permissions, and
the system grants them separately.

### 1.3 The tools installed on the operator's own machine

Separately from the catalogue above, the system keeps a **roster of programs it
will actually launch on the operator's own computer**. This roster is
deliberately short. Its own source comment describes it as restricted "to what
the code actually spawns… not an aspirational arsenal; every entry is traceable
to a call site." In other words, the system refuses to advertise a tool it does
not really use.

**Required (6).** Without these, live operations that need them will refuse to
run rather than pretend.

| Tool | What it does, in plain terms |
|---|---|
| `nmap` | Finds which network doors on a machine are open and what is behind them. |
| `httpx` | Quickly checks which web addresses respond and what software appears to serve them. |
| `nuclei` | Runs a large library of community-written checks for known weaknesses. |
| `ffuf` | Systematically guesses hidden pages, folders and form fields on a web site. |
| `sqlmap` | Confirms database-injection weaknesses. Its findings are never accepted as proof. |
| `hydra` | Tries passwords against a login. Marked destructive; requires the highest authorisation and a multi-person sign-off. |

**Optional (7).** Used when present; the system carries on cleanly without them.

| Tool | What it does, in plain terms |
|---|---|
| `semgrep` | Reads source code looking for dangerous patterns. |
| `joern` | A deeper source-code analyser that traces how data flows through a program. |
| `tshark` | Records and summarises network traffic. |
| `chromium` | A web browser run without a window, so the system can see a page exactly as a real browser would render it. |
| `nikto` | Checks a web server for common misconfigurations. |
| `wapiti` | Scans a web application for common weaknesses. |
| `zaproxy` | A well-known open-source web application scanner. |

A few details in this roster are worth a government reader's attention, because
each one is a small refusal to overstate.

- **Burp Suite is deliberately absent.** The system can talk to Burp Suite (a
  widely used commercial testing proxy) through its network interface, but it
  never launches a Burp program. So it does not list Burp as an installed tool.
  Reporting the status of a program it does not launch would, in the code's own
  words, be "a fabricated status."
- **The interface never shows a false green.** Each tool is reported as one of:
  *installed*, *missing*, *failed*, *shadowed*, or *unsupported*. "Shadowed" is
  a genuine trap in this field — one of the required tools shares its name with
  an unrelated program that is commonly present on the same machine. If the
  wrong program is found, the system reports "shadowed", not "installed".
- **On a non-Linux computer, nothing is faked.** These tools are Linux packages.
  On any other operating system every tool reports "unsupported" and nothing is
  installed.
- **Installing a tool requires a human "yes".** During setup, the installer asks
  before installing anything. If it is run unattended without an explicit
  approval flag, the answer is treated as *no*. At runtime, the system can offer
  to install a missing tool from the roster, but only using that tool's own
  pre-declared installation command, never a command supplied by whatever asked.
  Without explicit consent the request comes back as "needs consent". Automated
  parts of the system therefore cannot change what is installed on the machine.
- **A missing tool never stops the setup.** It is recorded with the exact command
  the operator needs to run, and installation continues.

### 1.4 The tools inside the isolated container

There is a third, separate list: the tools that live **inside an isolated
container** — a sealed, disposable Linux environment — used by an optional
autonomous testing agent. These are *not* installed on the operator's computer,
are never checked for on it, and are never installed by the setup process.

There are 24 of them. **You do not need to recognise these names.** They are set
out here only so that an operator, an auditor or a security officer can know
exactly what is inside that sealed environment, with nothing withheld. Grouped by
what they are for:

- *Finding machines and open network doors:* `nmap`, `naabu`, `ncat`.
- *Finding a web site's addresses and pages:* `subfinder`, `httpx`, `katana`,
  `gospider`, `dirsearch`, `arjun`, `ffuf`.
- *Testing a web application:* `nuclei`, `sqlmap`, `wapiti`, `zaproxy`,
  `wafw00f`, `jwt_tool`, `interactsh-client`.
- *Reading source code:* `semgrep`, `bandit`.
- *Finding passwords and keys left in code:* `trufflehog`, `gitleaks`.
- *Listing software components and their known flaws:* `trivy`.
- *Browsing and recording web traffic:* `chromium`, `caido-cli`.

Using this surface requires container software (Docker) and a locally built
image. It is entirely optional.

The system's own deployment guide states the honest caveat about this agent
plainly: **its output is leads, not proven facts.** The evidence and
proof-checking machinery that turns a finding into a signed, re-checkable fact
does not run over the agent's output. The guide instructs the reader to treat
those results as investigative leads to confirm.

### 1.5 The narrow gate through which network tools are actually run

Even the six required tools cannot be run freely. The part of the system that
executes them accepts exactly six programs — `nmap`, `nuclei`, `httpx`, `ffuf`,
`sqlmap`, `hydra` — and builds each command line itself from a fixed template.
There is no free-form command. There is no command shell involved, so there is
no way to smuggle extra instructions into an argument. Where a password would
otherwise appear on a command line, it is masked in the signed record of what
was run.

Two additional, non-network execution routes exist and pass through the same
gate:

- A **governed local terminal** that can run only a short list of read-only
  inspection commands (things like listing files, showing disk usage, checking
  who is logged in). It cannot reach the network, cannot write files, and cannot
  start a programming interpreter — not because a filter forbids it, but because
  the construction makes it impossible. Any shell special character causes the
  whole command to be refused.
- A **sealed sandbox** that can run an arbitrary command, but inside a container
  whose network has been removed at the operating-system level, and which can
  write only to one scratch directory. If the sandboxing program is missing or
  unusable, the system **refuses to run the command at all**. There is
  deliberately no fallback to running it unprotected.

Both of these route to the same approval machinery as everything else, and both
sit above the automatic-approval ceiling, meaning they queue for a human by
default.

### 1.6 Reading a report produced by a tool you already run

Everything above is about tools this system *runs*. There is a second, quieter
route that matters to any organisation with an existing security toolchain: this
system can also **read the report another tool produced**, without running that
tool at all.

An operator can hand it an export from a tool the organisation already owns and
operates, and the system will ingest the findings. Eight input formats are
accepted: reports from `nuclei`, `zap`, `burp`, `sqlmap`, `nikto` and `wapiti`; a
standard machine-readable format for security-tool output used across the
industry (SARIF); and a plain, generic list of findings for anything else. The
system will also try to recognise which of those it has been given, and will ask
for the format to be named when it cannot tell.

The rule from section 1.1 applies without exception. Everything read in this way
enters as a **lead**, tagged with where it came from. It is deliberately not
recorded as a finding, because a finding is reserved for something one of the
system's own fixed tests has proved. Where one of those fixed tests can be run
over the imported claim, it is run; a claim that cannot be re-proved stays a
labelled lead and says so. Importing the same report twice changes nothing, so an
operator cannot accidentally inflate a count by re-running an import.

The practical effect is worth stating plainly, because it is the answer to "how
does this fit alongside the tools we already have?" It fits by treating them
exactly as it treats its own: as sources of suggestions, whose claims are only as
good as the evidence the system can collect for itself.

### 1.7 A general bridge for other tools — and its honest limit

The system includes a general-purpose bridge designed so that *any* external tool
can be plugged in and still produce a proven fact. The bridge runs in a strict
order and stops at the first failure:

1. Check the emergency stop, the authorisation document, and the operator's
   permission.
2. Check the target is in scope. **If it is not, the tool is never launched at
   all** — no traffic leaves.
3. Check the execution environment is available. If it is not, the bridge stops
   rather than quietly falling back to something less protected.
4. Run the tool.
5. Take each thing the tool claims and **re-prove it independently** with the
   system's own controlled attempt and its own fixed test.

Before any tool can be marked as fact-capable, it must pass an acceptance battery
that runs *through the real bridge, never a simulation*. There are five parts,
and all five must pass:

| Test | What it proves |
|---|---|
| **The genuine case** | A real weakness produces a proven finding that can be re-checked later, offline, from the stored evidence. |
| **The deceptive case** | A tool that claims something the system's own re-test cannot reproduce mints **nothing at all**. This is the anti-lying test, and it is the reason the whole battery exists. |
| **The broken-tool case** | A tool that errors or fails is handled honestly, rather than its silence being read as a clean result. |
| **The emergency-stop case** | With the emergency stop engaged, the run refuses **before any traffic leaves**. |
| **The out-of-scope case** | For a target outside the authorised list, the run refuses **before any traffic leaves**. |

The battery is scored strictly: a report counts as passing only if **every**
required property is present and true. A property that is simply missing is
treated as a failure, never as satisfied by default. That detail matters more
than it looks — "we did not check" quietly becoming "it passed" is one of the
commonest ways an assurance process rots.

**Honest status.** One tool has been run this way for real: a genuine `nmap` run
against a deliberately started local service, producing exactly one signed,
independently confirmed fact — with a closed or non-reproducing port correctly
becoming a lead rather than a fact. The container-based execution route is built
and produces the real command line, but its live container run depends on
container software and a tool image being present. A set of AI-red-teaming tools
that the bridge is designed to accept are simply **absent from the current
environment**, and the code says explicitly that it does not mint facts from
them.

### 1.8 Other people's software kept inside this one, and deliberately not run

Two code bases written by other projects are kept inside this system's own source
code. (In the software trade this is called *vendoring* — keeping your own copy of
somebody else's programme inside yours, rather than downloading it fresh each
time.) The two are treated very differently from each other.

- One is a large published AI-security tool collection. It is included **in a
  non-runnable, quarantined form**. An automatic build check fails the whole
  build if any part of the system ever tries to use it. What the system does
  instead is a clean re-implementation of the *idea* — a planner that can suggest
  where to look, with no network effects at all, no evasion features, and no
  authority to declare anything a fact. The original's evasion and stealth
  features, its credential-poisoning features, its web-firewall-tampering
  features and its live exploitation and persistence stages were **left out by
  construction, not removed afterwards**.
- The other is an automated penetration-testing tool included under its original
  open-source licence, with the original authors' credit preserved. Its ability
  to run arbitrary commands is the point at which a human is asked. That gate is
  on by default; turning it off requires an explicit setting.

  **One note on that gate, because it is the most dangerous single surface in the
  system.** The gate is on by default, switching it off deliberately is a visible
  act, and the attachment itself fails closed: if attaching the gate raises an
  error, the run stops rather than falling back to the ungated original. The one
  case that is not a failure is a bare copy of the third-party tool running on its
  own, without the connecting software — there is nothing to govern there, and the
  vendored copy is meant to behave exactly as its authors shipped it. Chapter 8
  covers this gate in full.

### 1.9 How the system was measured against those same tools

The project ran a direct comparison on its own machine against a purpose-built
web application containing **11 deliberately planted weaknesses** and **5
deliberately clean pages** that must never be flagged. The result is committed as
a signed file that can be re-derived and compared line by line.

| Tool | Correctly found | Flagged wrongly | Missed |
|---|---:|---:|---:|
| **This system** | 11 | **0** | 0 |
| `sqlmap` | 0 | 0 | 11 |
| `wapiti` | 2 | 7 | 9 |
| `nikto` | 0 | 8 | 11 |

The project's own written caveats on that table are longer than the table itself,
and they are the reason it can be shown to a sceptical reviewer at all:

- **The "flagged wrongly" column is not a noise score.** It counts anything that
  did not match a planted weakness under a strict matching rule, which lumps
  together genuine false alarms and real detections that were made under a
  different name or at a coarser location. Some of the other tools' counted
  misses were real hits. The document instructs the reader not to treat those
  numbers as "work a human must triage."
- **The perfect score is partly a home-field advantage, and the document says
  so.** The answer key uses this system's own vocabulary and its own level of
  precision about *where* a weakness is. The same strict matching that gives this
  system a clean sweep penalises the others in both directions.
- **`sqlmap` is a database specialist scored on a board where nine of the eleven
  weaknesses are not database weaknesses.** A zero there means "a single-purpose
  tool on a multi-purpose test", not "this tool is broken." The document states
  that it is included because practitioners commonly reach for it, and that the
  zero is an artefact of what the test board contains rather than a verdict on the
  tool.
- **The narrow claim actually being staked** is the honest, portable one: every
  finding this system reported was confirmed by its own test and can be
  re-checked offline by someone else, and it flagged **none** of the five clean
  pages.
- **Soundness is not completeness.** "No false alarms" never means "found
  everything." Coverage is measured separately and a miss is reported as a miss.

The relevance to this chapter is simple. The other tools are not competitors the
system is trying to beat. They are inputs it is trying not to trust. The
measurement above exists to show that the refusal to trust them has a measurable
consequence, not merely a rhetorical one.

---

## Part Two — What You Need To Run It

### 2.1 The short answer

**No product bought from another software vendor is strictly required to bring the
system up.** The example configuration file states plainly that no secrets are
needed to start the stack, and that every commented line in it is an optional
override. There is one important exception, and it is a licence rather than a
piece of software; it is set out at the end of this section, and a public-sector
reader should read that part first.

That is not a marketing claim; it follows from how the system is built. The parts
that decide whether something is a real finding — the fixed tests, the signing,
the verification, the permission chain, the offline checkers — are ordinary
deterministic code. They need no artificial-intelligence service, no account and
no key. The AI's job is only ever to *propose* where to look. If there is no AI
key configured and no scripted plan supplied, an operation still starts, still
records who authorised it, and then **completes having proposed nothing**. It
never invents activity to fill the silence.

Sections 2.2 onwards are therefore a ladder of what each extra thing *buys you*,
not a list of blockers.

#### The exception: you do need a licence, and for a government body it is a paid one

This is the first practical question for a public-sector reader, and it is not a
technical one.

The software's own code is offered under two alternatives. The first is a free,
source-available licence (PolyForm Noncommercial 1.0.0) that allows anyone to use,
study, modify and share the software for non-commercial purposes. The second is a
paid commercial licence agreed directly with the copyright holder.

Attached to the free licence is a supplemental term that a government reader must
not skim past. In its standard form, the free licence treats government
institutions as an acceptable non-commercial user. **This software deliberately
removes that.** Written into the licence file is a Government-Use Supplemental
Term stating that use by, for, on behalf of, or funded by any government,
government agency, department, ministry, military, intelligence service,
law-enforcement body, public authority, state-owned enterprise, or other
public-sector entity is **not** a permitted non-commercial purpose and requires a
separate commercial licence — even where the use would otherwise plainly be
non-commercial. The supplemental term is written to override anything to the
contrary in the free licence text.

In plain terms: **a government body cannot use this system under the free
licence.** It must obtain a commercial licence from the copyright holder. Charities,
schools and public-research organisations that are not government entities remain
covered by the free licence.

Two boundaries of the free licence are worth stating in the same breath, because
they catch people out. It does not cover **selling** the software or a service
built on it, and the licensing document is explicit that it does not cover running
it **in production for a for-profit organisation** either. So the free route is for
study, research, personal use and non-commercial work by non-government bodies.
Everything else — government use, commercial use, production use — is the paid
route.

Two related points, both stated in the project's own licence documents:

- **The third-party components keep their own licences.** The automated
  penetration-testing tool described in section 1.8 remains under the Apache 2.0
  licence; some adapted portions remain under the MIT licence; the AI-red-teaming
  subprocess tools keep their own upstream terms. None of these are changed by
  the dual licence above, and the attribution file lists them.
- **No warranty, and responsibility for use rests with the user.** The licence
  states directly that the software contains autonomous offensive security
  tooling, that it is to be used only against systems the user owns or has
  explicit written permission to test, that it is provided "as is" without
  warranty, and that the licensor accepts no liability for use or misuse. A
  commercial agreement is the route by which warranty, indemnity or support terms
  can be negotiated; the free licence provides none of them.

Nothing in this chapter is legal advice, and the licence files are the binding
texts. This section exists so that a procurement officer knows, on the first
reading, that a licensing conversation is required rather than optional.

### 2.2 Hardware and operating system

| Requirement | Why | If you do not have it |
|---|---|---|
| A Linux computer | The security tools it drives are Linux packages. | On any other operating system the tools are reported "unsupported" and nothing is installed or faked. The rest of the system is unaffected. |
| Python version 3.12 or 3.13 | Builds both halves of the system. | **Hard stop.** Setup refuses to continue. |
| The Rust toolchain | Builds the small, fast component that classifies how risky each action is. | Setup offers to install it for you, at user level, with your consent. |
| Container software (Docker) with compose | Runs the optional memory database and the optional knowledge graph; **required** for the optional autonomous agent. | Optional for the core. The memory database falls back to an embedded, file-based mode. |
| A security chip (TPM) plus its tools | Encrypts stored keys so they are useless if the disk is moved to another machine. | Optional. Without it, keys are stored unencrypted on disk. Setup prints a loud warning; it never quietly weakens protection without telling you. See section 2.6, step 4, and section 2.7. |

#### What it costs to run — stated honestly, including the silences

Two questions come next in every procurement conversation: *how big a machine?*
and *how much will an operation cost?* The honest answer differs for each.

**Machine size: not published.** The repository publishes no minimum figure for
memory, processor cores or disk space, and this chapter will not invent one.
Treat sizing as an engineering exercise for your own environment. What can be said
factually is that the system is designed to run on a single ordinary Linux
computer, that its heaviest optional pieces are the container services (the memory
database, the knowledge-graph database and a telemetry collector), and that all
three are optional — the memory database falls back to a file-based mode that
needs no container at all.

**How long a run takes and how much traffic it sends: not published as a
benchmark, but bounded by settings you control.** No timing or throughput figures
are published, and the chapter will not estimate them. What *is* fixed in the code
and visible to an operator are the limits:

| Limit | Default | What it means |
|---|---|---|
| Actions in one operation | 1,000 | The operation stops when the count is used up. |
| Requests the gated sender will issue | 100 in the executor; 200 in a standard operation | A hard ceiling on how many web requests are sent. |
| Pages crawled, and how deep | 100 pages, 6 links deep | How much of a site is mapped. |
| The polite intake scan | 50 requests, one at a time, roughly a third of a second apart | Used when drafting a new engagement from a web address. |
| Time window | 8 hours | The signed authorisation expires. |

Pacing is set by the operating posture written into the authorisation document,
and it changes the elapsed time directly: the ordinary testing posture waits at
least 0.2 seconds between requests; the audit posture waits at least 1 second; the
adversary-emulation posture waits at least 5 seconds plus up to 3 seconds of
random variation. A thousand actions at 1 second apart is a very different
afternoon from a thousand at 0.2 seconds apart, and the operator chooses which.

**AI spend: metered and cappable, not predicted.** If you connect a commercial AI
service, you pay that provider directly for what the system asks it. No expected
figure is published. What the system does provide is the ability to *cap* it: a
per-agent daily budget file sets limits on the number of actions, the number of
interruptions, the number of provider tokens and the money spent in a day, and the
limits are enforced by refusing the action rather than by warning after the fact.
Budgets are optional; with none set, nothing is capped. A read-only command
reports the day's usage. If you use only local AI running on your own hardware, or
no AI at all, there is no provider bill.

### 2.3 Accounts, credentials and keys — the complete list the system will hold

**First, one term used throughout this section.** An **API key** is simply a long
secret string that an online service issues to a customer so that a programme —
rather than a person typing a password into a web page — can prove which account
it belongs to. It is closer to a season ticket than to a password: whoever holds
it can use the service and be billed for it, so it must be protected exactly like
a password, and it can be cancelled and re-issued by the service if it leaks. Some
services also issue a *pair* — an identifier plus a secret — and some issue a
short-lived *token* that expires on its own. All three appear in the table below.

The system keeps a **closed list** of the credentials it is willing to hold. It
knows the name of every one in advance, and an unrecognised name is refused
outright, so the interface cannot be talked into storing an arbitrary secret for
something it has never heard of. There are 17 entries on that list, and they are
set out in full below.

Credentials are sealed on the machine and are **never sent back to the browser**.
Where a live health check exists, the interface shows whether the key is actually
working — a revoked or mistyped key shows as *failing*, not as a reassuring
green tick. Twelve of the seventeen have such a live check.

| Credential | What it is | Required? | What it buys you | Live health check? |
|---|---|---|---|---|
| Anthropic (Claude) API key | Access to a commercial AI reasoning service. | Effectively required if you want AI-assisted reasoning; **not** required to run. | Lets the AI propose where to look during operations, scans and fix suggestions. | Yes |
| Mistral API key | Access to a European AI service. | Optional | An alternative AI provider. | Yes |
| OpenAI API key | Access to another commercial AI service. | Optional | An alternative AI provider for the autonomous agent. | Yes |
| Perplexity API key | Access to an AI web-research service. | Optional | Lets the agent do live web research during a source-code review. | Yes |
| Azure OpenAI API key | Access to AI models hosted in Microsoft Azure. | Optional | An alternative AI provider; also needs the endpoint address. | Yes |
| AWS access key id | Amazon Web Services identity. | Optional | Read-only checks of an Amazon cloud account's security settings; also unlocks Amazon-hosted AI models. Checked by asking Amazon "who am I?". | Yes |
| AWS secret access key | The secret half of the Amazon pair. | Optional (paired) | As above. | Checked via the pair |
| AWS session token | Only for temporary Amazon credentials. | Optional | Supports short-lived or single-sign-on Amazon sessions. | Checked via the pair |
| Azure client secret | A Microsoft Azure service identity's password. | Optional | Read-only checks of an Azure subscription's security settings. Checked by requesting a sign-in token. | Yes |
| Google Cloud service-account key | A Google Cloud identity file, pasted whole. | Optional | Read-only checks of a Google Cloud project. Checked by minting an access token. | Yes |
| Kubernetes configuration | The connection file for a container cluster. | Optional | Read-only checks of a Kubernetes cluster. One kind of configuration file is refused — see the note below the table. | Yes |
| GitHub token | Access to your source-code hosting. | Optional until you want automatic fixes | Lets the system propose a fix and open a *pull request* — a formal, reviewable proposal to change the code, which a human on your team must approve before anything is merged. Needs repository and pull-request permission. | Yes |
| ElevenLabs API key | A text-to-speech service. | Optional | Spoken output on the personal-assistant side. **Never passed to the offensive side.** | Yes |
| Gated-API shared secret | A password you invent yourself. | Required only if you host the console behind a domain name | Protects the controlled interface. No outside service is involved. | No outside service to check |
| Out-of-band callback secret | A password you invent yourself. | Optional, but see the note on the call-back relay below — it is a hard requirement for a whole class of findings against a remote target | Protects the small call-back server the operator runs. No outside service is involved. | No outside service to check |
| Neo4j password | Password for a graph database. | Optional until you connect one | Stores a rebuildable map of what was learned. It holds no secret and grants no permission. | Yes |
| Auto-patch signing key (owner) | A key you generate yourself. | Optional until you open pull requests | Authorises the system to open a code-fix pull request. Deliberately withheld from the offensive side of the system. | No outside service to check |

Alongside these there are non-secret settings that are shown openly rather than
masked: Amazon region and role, Azure tenant/client/subscription identifiers,
Google Cloud project, Kubernetes context, and graph-database address and
username. An identifier is not a secret.

There is also a second owner key, used to sign per-action approvals. Like the
auto-patch key, it is read from the environment and never passed on a command
line where it could appear in a process listing.

**The Kubernetes note, in full, because the table row is too short to be
useful.** A Kubernetes connection file describes how to log in to a container
cluster. There are several ways it can do that. Two of them hand over a
credential directly: a *token* (a long secret string) or a *client certificate*
(a small file that proves identity, like a sealed pass). A third kind does
something quite different: instead of carrying a credential, it carries an
instruction to **launch a helper programme on your own machine** and use whatever
that programme prints. That style is very common with cloud providers, because
the helper fetches a fresh short-lived credential each time.

This system refuses that third kind outright, and refuses it *before* the file is
loaded rather than after. The reason is simple and worth understanding: honouring
it would mean this system runs a programme named inside a file that was pasted
into a web form. A file supplied by someone else could then name any programme on
the machine. So the refusal is not a limitation of the cloud check — it is a
deliberate boundary around what a pasted file may cause to happen.

*What to do instead.* Supply a connection file that carries a token or a client
certificate. Every major Kubernetes platform can produce one: create a service
account with read-only permissions in the cluster, issue it a token, and build a
connection file that embeds that token and the cluster's address and certificate
authority. That file is self-contained, needs no helper programme, and is what the
system will accept. It is also the better practice for an automated read-only
reviewer, because it can be scoped tightly and revoked on its own without
touching a human's login.

#### Two things an operation needs that are *not* on that list

The seventeen entries above are the complete list of credentials **this system
will store for itself**. They are not the complete answer to "what do I need to
run a real operation." Two further inputs come from your side, and both change
what the system is able to find. Leaving them out is the commonest way an
operator gets a disappointing first result.

**1. Test accounts on the application you are testing.** Most of a real
application's interesting surface is behind a login. Ordering, payments, admin
screens, other people's records — none of that is visible to an anonymous
visitor. The system contains a component that keeps a login session alive while
it works: it holds the site's cookies, performs the login sequence you describe,
notices when the site has logged it out (a refusal, or a "you are signed out"
marker on the page), and logs back in before retrying. In plain terms, it behaves
like a tester who stays signed in rather than one who keeps getting shown the
front door.

Be precise about what is built and how you reach it, because they are not the
same thing:

- The session-keeping component **is built and tested**, and can be composed into
  a scan by a programme. It is a building block, not a button.
- The **access-control pack** — the tests for "can one user read another user's
  records?" — is exposed on the command line and is switched off by default. It
  is fundamentally a **two-identity** experiment: act as one user, and compare
  against what a *different* user legitimately sees. There is no safe way to guess
  those identities, so the operator supplies them: a header carrying the second
  identity's session, plus the specific record references to attempt to cross-read.
  Enabled without those inputs, the pack builds nothing at all and says so — it
  never guesses.
- The current command-line runner does **not** carry a flag for logging the
  primary identity in with a username and password. That path exists in the code
  as a component to be composed, not as a command-line option. State this
  accurately in planning: if your engagement depends on scanning deeply behind a
  login, expect either to supply session headers or to have an engineer wire the
  session component in.

Practically, your organisation should prepare, before day one: two test accounts
at different privilege levels on the target application, the exact login steps,
and a short list of record identifiers each account owns. These are yours to
create; the system cannot conjure them.

**2. A call-back relay, if the target is not on the same machine.** Some of the
most serious weaknesses are invisible in the reply the tester receives. The
application is tricked into reaching out to somewhere else — a different server,
an internal address — and the visible response looks entirely normal. The only
proof is the **inbound** connection arriving at infrastructure the tester
controls. Think of it as ringing a doorbell you have installed yourself: you
cannot see inside the house, but if your bell rings, someone in there pressed the
button.

The system ships that doorbell in two forms:

- A **local receiver**, which needs nothing from you. It listens only on the
  machine itself. That works when the target application is running on the same
  computer as the tester — and only then.
- A **relay you host yourself**, for everything else. A remote target cannot reach
  a listener that only exists on the tester's own machine, so for a remote
  engagement the operator runs a small server on a host they own, and puts that
  host on the engagement's authorisation document. The system's own description of
  this is precise about the sovereignty point: it is a call-back service you
  **host**, not one you rent from a vendor. Reading the recorded call-backs
  requires a shared secret, compared in a way that does not leak it, and carried
  in a request header so it never lands in a web server's access log. If the relay
  is anywhere other than the tester's own machine, the system **refuses a plain,
  unencrypted address** — you front the relay with an encrypted connection and give
  the system the secure address.

**Why this matters commercially and operationally.** Without a relay, four of the
eleven always-on checks that a standard operation runs — the ones for
server-side request forgery, unsafe file parsing, remote command execution and
unsafe data deserialisation — plus every other weakness that can only be proved by
a call-back, will produce **nothing** against a remote target. The system does not
guess in their place; it skips them and records that it skipped them. An operator
who is unaware of this would run an engagement, see no findings of those types,
and wrongly conclude the target was clean. One honest limit is documented and
should be carried into planning: the relay handles call-backs that arrive as web
requests. A call-back that is only a name look-up, with no web request following
it, needs a name-service relay, which is described in the code as a future
extension rather than something quietly implied to work today.

### 2.4 Keys you generate yourself, not buy

Four of the most important keys in the system are not purchased from anyone. You
create them:

- **The approval key.** One command mints it. It is printed **once** and never
  stored by the tool that created it. It is the key that signs "yes, do this one
  specific action."
- **The destruction quorum keys.** One command mints a set of keys and a
  threshold — for example, three keys of which two must agree. Each private key
  is printed once and explicitly not stored. The command warns that if you set
  the threshold to one, whoever holds the owner key can authorise on their own.
- **The offensive side's own identities.** The offensive half of the system holds
  a stable identity used to sign its records. It never holds the owner key. When
  identities are exported for the owner to bless, **only public keys are
  exported** — the command's own wording is that no private key ever crosses.
  The command also warns that this file must travel over a channel you trust,
  because a swapped file would get an attacker's key blessed.
- **The two shared secrets** (the gated-API secret and the call-back secret) are
  simply passwords you choose.

The design rule behind all of this is worth stating in one line: **the sovereign
side holds the owner key; the offensive side is keyless with respect to owner
authority.** One of the keys is not merely left out of the offensive side's
environment — it is actively stripped from it, so that a compromised offensive
process cannot authorise its own destructive action.

### 2.5 Network access, listening services and things that run on a schedule

**Inbound: none from the public network.** The system's own deployment guide
states that it never binds a public network interface. Every service it starts
listens only on the machine itself. The program that starts the interface refuses
outright to listen on a public address; it will accept only the local machine, a
private corporate address range, or a private virtual-network address. A
deployment behind a domain name with the shared secret unset is refused unless the
operator passes an explicit "yes, I know this is insecure" flag. Remote access is
expected to be through an encrypted tunnel plus a reverse proxy that you run.

#### Everything that listens, in full

"Listens only on the machine itself" is the correct summary, but a security
reviewer inventorying attack surface needs the list, not the summary. Here is
everything in the box that opens a listening port or accepts a connection, what
it is for, and how it is reached.

| What listens | Address and port | Started how | What it is |
|---|---|---|---|
| The unified interface proxy | Local machine, port 8770 | Only by the operator's "bring it all up" command | The single web address a human points a browser at. It sits in front of the three services below and presents them as one site. |
| The sovereign cockpit | Local machine, port 8733 | Same command, or its own command | The personal-assistant half's own screens. |
| The offensive console | Local machine, port 8787 | Same command, or its own command | The offensive half's read-only screens and its live event feed. |
| The offensive action interface (the "API daemon") | Local machine, port 8799 | Same command, or its own command | A **programmatic** way to drive and observe the system — for an integrator who wants their own orchestration software to talk to it rather than a person clicking. See the note below. |
| The optional memory database | Local machine, ports 6333 and 6334 | Only if you start the container services | Stores the searchable memory of past work. |
| The optional knowledge-graph database | Local machine, ports 7474 and 7687 | Only if you start the container services | Stores the rebuildable map of what was learned. |
| The optional telemetry collector | Local machine, port 4318 | Only if you start the container services | Receives the system's own internal measurements. Its only permitted onward destination is this same machine. |
| The out-of-band call-back relay | A host **you** own, on a port you choose | Only when the operator runs it, for a remote engagement | The doorbell described in section 2.3. This is the one component that is *meant* to be reachable from the target, so it is the one place where inbound traffic is intended. |
| The witness co-signing service | Local machine, or a private tunnel address | Only if you install and enable it | A second party that counter-signs records. Its server refuses a public address outright. |

Every one of these is off until an operator deliberately starts it, and every
container service publishes its port on the local machine only, never on a public
interface. The relay is the only one of them that is *meant* to accept a
connection from outside the operator's own machine, and it is the operator's own
infrastructure on a host the operator named in the authorisation document.

**Two programmatic entry points, named plainly.** Chapters elsewhere describe two
ways in — the screens and the command line. There are two more, and a reviewer
inventorying the system's attack surface should know about both:

- **The action interface** (port 8799 above). It exists so that an organisation
  can drive the system from its own software. Its own description of itself is
  worth quoting in plain terms: nothing runs unless the operator starts it; it
  binds to the local machine only and refuses any other address; the majority of
  it is read-only enquiries; and **every action it accepts goes through exactly
  the same permission chain as a local action** — the emergency stop, the
  entitlement check, the scope check, the destructive-action check, the
  outbound-traffic check. That chain is *fail-closed*, a term worth defining once:
  like a drawbridge held up by an electric motor, if the power is cut it falls
  shut. If any check cannot be completed — an error, a missing file, an
  unreadable setting — the answer is no, never a shrug and a "proceed anyway".
  It exposes no capability that is not gated. It serves no
  files, so there is no file-path attack surface at all. Request bodies are size-
  limited and read only as structured data — never executed. A request from
  another web site is refused. It has an optional shared-secret requirement,
  switched off by default, for the one case the local-only binding does not cover:
  an operator who deliberately places it behind a tunnel or proxy. That secret
  travels in a request header, never in a web address where it would land in a
  proxy log, and it is compared in a way that does not leak it.
- **A tool-server interface for other AI systems.** This lets another AI assistant
  or agent enumerate and call a curated set of this system's capabilities. It
  speaks over the programme's own input and output streams rather than over a
  network, so it opens no port at all and is inherently on-host. It is
  default-safe: it advertises and permits **only** capabilities that are low-risk,
  need no entitlement, are non-destructive and send no outbound traffic. An
  offensive capability is not even listed, and a call to one is refused before it
  reaches the permission chain. Crucially, the engagement it runs under is fixed
  when the server is started and can never be chosen by the caller, so a remote
  caller cannot widen its own scope. Anything it returns is labelled as an
  observation — a lead — never a proven finding.

#### Things that run on a schedule, once you enable them

The system ships ready-made background service definitions for Linux. **None of
them is installed or enabled by default.** An operator copies them into place and
switches them on deliberately. They matter to an operations team because, once
enabled, they cause the machine to do work on a timer without anyone pressing
anything:

| Scheduled unit | Default cadence | What it does |
|---|---|---|
| Continuous re-proof | Every 6 hours, spread by up to 5 minutes so many machines do not fire at once | Re-runs a retained proof against the live target and appends a fresh signed entry to the running record, with a witness counter-signing the new head. This is what turns "continuously re-proven" from a capability into something that is actually happening. |
| Posture re-proof | 5 minutes after start-up, then every 30 minutes | Re-scans the authorised target, re-issues the signed statement of its security posture, and appends it to a tamper-evident series that refuses to go backwards. |
| Witness co-signing service | Runs continuously once enabled | The counter-signing party used by the re-proof above. |
| Nightly memory consolidation | 03:17 local time, daily | Offline processing of the personal-assistant half's memory. Deliberately offline: it spends nothing with an AI provider. |
| The cockpit, and the phone bridge | Run continuously once enabled | The personal-assistant interface, and its encrypted-tunnel link to a phone. Both refuse a public address. |

Two honest points about the timed re-proofs, taken from the units' own notes.
First, freshness is only ever as current as the **last** run of the timer:
"continuously re-proven" means "re-proven on this cadence", not "provably true at
this instant." Tighten the cadence if you need fresher assurance. Second, the
target must actually be reachable at the moment the timer fires; an unreachable
target produces an honest failure entry, not a silent pass.

**Outbound: only what you switch on.** The categories are:

| Destination | When | Optional? |
|---|---|---|
| The target you are authorised to test | During an operation | Required for a live test; strictly limited to the signed scope |
| Your chosen AI provider | Only when AI reasoning is enabled and the provider is a cloud service | Optional — local AI providers need no outbound access |
| Four public look-up services (a public DNS resolver, a certificate transparency log, a domain registration look-up, and a network-numbering statistics service) | Only when live background research is switched on | Optional, and off unless enabled |
| Your cloud provider's management interface | Only when cloud credentials are configured | Optional |
| Your source-code host | Only when automatic fixes are used | Optional |
| Your graph database | Only when one is configured | Optional |
| Your own call-back relay, on a host you own and have named in the charter | Only when you run one, for a remote engagement | Optional, but required for the blind checks — see section 2.3 |
| Your chosen key providers | When you press "test key" | Optional |

The barrier around outbound traffic is not a preference setting. It is enforced
twice, and the second layer is outside the reach of anything the system is
running:

- At the network level, firewall rules drop everything from the sandbox except
  two destinations: the system's own filtering proxy and its own name resolver.
  The code describes this as "the layer a prompt-injected agent cannot argue
  with." Because there is no direct route out, an agent that unsets its own proxy
  settings gains nothing — the packets are dropped by the host.
- At the application level, a filtering proxy runs **outside** the sandbox's
  control. It resolves the destination name once, refuses the whole connection if
  *any* returned address is forbidden, and then pins the connection to that exact
  verified address so the name cannot be switched underneath it.

Certain address ranges are **permanently forbidden and cannot be re-enabled by
any authorisation document** — most importantly the special address that cloud
machines use to fetch their own credentials. The reasoning is written into the
code: a document listing that address is far more likely to be a mistake or an
injected instruction than a genuine intent to let the system read the host's
cloud credentials.

### 2.6 Day one: what an operator actually does

The following is the real sequence, in order.

**Step 1 — Install.** Clone the repository and run the single setup script. It
performs six steps, and re-running it is harmless where work is already done:
check prerequisites, build the two halves of the system, start the optional
memory service on the local machine only, write the configuration and the
launcher commands, seal keys to the security chip if one is present, and run a
smoke test. Useful variations exist for building the sandbox image, skipping
services entirely, installing background services, and running unattended.

*A deployment-time decision belongs here, and a government buyer should ask about
it explicitly: is this a **governed** installation or an ungoverned one?* The
system's most dangerous capabilities do not become available merely because the
code is sitting on a disk. They are released by an **entitlement** — a signed
permission document, issued by a set of authorisers, that can be bound to a
specific host, that expires, and that can be revoked. Capabilities are arranged in
four rising levels: a baseline that always works (the reasoning core, and the
passive intake described later), a standard level (active probing within scope,
autonomous planning, and active blocking on the defensive side), an offensive
level (running an exploit, deep source-code analysis, self-detection scoring), and
an advanced level (chaining several weaknesses together, human-authored evasion,
and authority to merge the system's own improvements).

Enforcement switches on when a **trust root** is installed — that is, the list of
who is entitled to issue those permission documents, and how many of them must
sign before one counts. Once a trust root is present, every gated capability is
checked in a fixed order and the first failure wins: are enough valid signatures
present; is the permission document currently within its validity dates; is this
the host it was issued for; has it been revoked; and does it actually grant the
capability being asked for. Any failure is a refusal. The baseline capabilities
remain available in every case, including when a permission document is present
but invalid — the safe core never depends on one.

**The honest caveat, which matters and is easy to state wrongly.** With **no**
trust root installed and enforcement not explicitly switched on, the installation
is *ungoverned*, and in that state the higher capabilities **are permitted**. They
are not silently permitted: every such grant is recorded with a warning saying
that it was allowed only because no trust root is provisioned, and the system
reports plainly that it is ungoverned when asked. This deliberate default exists
so that a development copy works without ceremony.

So the answer to the question every buyer of offensive tooling asks — *if a copy
of this software is stolen, what can the thief do with it?* — has to be given
precisely:

- Copied from a **governed** deployment, without the matching permission document
  — or with one that has expired, been revoked, or was issued for a different
  host — the thief gets only the safe baseline. The dangerous capabilities do not
  release.
- Copied as **raw source code**, and set up fresh without any trust root, the
  copy is ungoverned, and the higher capabilities run with a warning rather than a
  refusal. The protection here is not the entitlement; it is the authorisation
  document, the signing keys and the approval chain, none of which the thief has.

The practical instruction for a government deployment is therefore short: **install
the trust root.** Chapter 8 covers this mechanism in full; it is noted here because
provisioning it is an installation decision, not something you can add on the day
of an operation.

**Step 2 — Run the health check.** A read-only command reports whether every
prerequisite is present, whether both halves are built, whether the working
directories are writable, whether the four local interface ports are free, and
which optional services are running. It changes nothing.

**Step 3 — Bring up the interface and open it.** One command starts everything
and prints a single web address for the local machine, including a one-time
session token. That address is the only thing a human points a browser at; it
federates the two halves of the system behind one origin. The main interface has
28 screens, including a Tools screen that shows, live, exactly which security
tools are present on this machine and which are missing, with a copyable install
command for each.

**Step 4 — Decide about key storage.** If the machine has a security chip, run
the vault provisioning step so keys are encrypted at rest and are useless if the
disk is moved. If it does not, understand and accept that keys sit unencrypted on
disk. The documentation calls this acceptable on a trusted single-user machine
and inadequate on a shared or hosted one. Existing unencrypted keys are migrated
without loss: the encrypted copy is verified to decrypt correctly *before* the
plain copy is replaced.

**Step 5 — Enter the credentials you actually want.** On the API Keys screen,
seal only the keys the planned operation needs. Press "Test" on each to confirm
it works. A failing key is shown as failing, and a count of failing keys appears
in the top bar.

**Step 6 — Write and sign the authorisation document.** This is the step that
matters most, and there is no way around it. The system will not touch a target
without a **charter** — a written document naming the systems in scope, an
attestation from the operator that they are authorised to test them, hard limits,
soft limits, stop conditions, and objectives. The in-scope systems are listed in
a numbered table, and the parsing is deliberately unforgiving: an empty scope
produces an authority that authorises nothing at all, on the grounds that an
empty scope almost always means something upstream went wrong.

*You do not have to start with a blank page.* The system includes an intake step
that turns a web address into a fully prepared engagement folder: a **draft**
charter, a draft threat model, a draft attack tree, and a structured record of what
the site appears to be built from. It gets that by a deliberately polite look at
public, standard locations — the site's front page, its instructions for
web crawlers, its site map, its published security-contact file, its
single-sign-on discovery document and a handful of standard paths — capped at 50
requests, one at a time, roughly a third of a second apart, sending no login
credentials and no test payloads. Seven detectors then infer the technology in
use, and the result is matched against nine common application shapes.

Two safeguards make this an on-ramp rather than a shortcut. The intake itself
**refuses to run** without a recorded operator attestation that the target is
authorised, so it is not a free scanning tool. And what it writes is a *draft*
charter, which it will never overwrite an existing signed charter with. **No
active testing happens until a human reads, edits and signs the real charter.**
The step below is therefore still mandatory; intake only removes the blank page.

Defaults are conservative by design: destructive actions off, a time-limited
window (eight hours by default) and a finite budget of actions (one thousand by
default).

Cloud and Kubernetes targets are authorised in a separate, additional section,
and by **identity, not by web address** — because authorising a shared cloud API
endpoint must not accidentally authorise every account that shares it. The tenant
must be named exactly. A blank, a wildcard, or the word "any" authorises nothing.

**Step 7 — Mint the signed authority.** A single command turns the charter into a
signed, scoped, time-boxed authority. The interface deliberately **cannot** do
this for a remote target: it will verify an existing authority and walk you
through the ceremony, showing you the exact command with the instruction to run
it on a trusted machine that holds the owner key — *not* in the browser.

**Step 8 — Set up approvals.** Mint the approval authority. From then on, when
the system wants to do something above the automatic ceiling, it publishes a
redacted request, and the owner signs a token for that one action. The token
names the exact tool, the exact target and a digest of the exact action; it
cannot be reused for anything else, it expires, and it can be spent exactly once.
Of many simultaneous attempts to use the same token, exactly one succeeds.

Crucially, **an approval token never widens scope.** It satisfies the "a human
said yes" requirement for an action the authorisation chain had already found to
be inside the envelope. An action the chain refused stays refused.

**Step 9 — Prepare the two inputs only your organisation can supply.** Section 2.3
sets these out in detail. Before the run, and not during it:

- If the target application has a login, prepare the test accounts and the login
  details, and decide how they will be supplied. If you intend to test whether one
  user can reach another user's data, prepare **two** identities at different
  privilege levels and the specific record references each one owns.
- If the target is **not** running on the same machine as the tester, stand up the
  call-back relay on a host you own, add that host to the charter, and note the
  shared secret. Without it, the four blind checks and every other
  call-back-confirmed weakness will be skipped. Front the relay with an encrypted
  connection; the system refuses a plain, unencrypted remote relay address.

**Step 10 — Run the operation.** Point the system at the authorised target within
the signed scope. Every action must clear all of the following, and the first
failure wins: the emergency stop is not engaged; the time window is current; the
target is in scope; destructive actions are permitted if this one is destructive;
a live target requires a second acknowledgement for a destructive action; the
action budget is not exhausted. On top of that, the action's own risk tier must
come back as automatically allowed, and if it is destructive, a multi-signature
authorisation including the mandatory owner must be present.

The automatic-approval ceiling is set at the second-lowest tier, which means in
practice that anything externally visible, anything that publishes or exports
data, and anything touching credentials, keys, permissions or production systems
**queues for a human and can never run on its own**.

**Step 11 — Stop, if you need to.** There is an emergency stop, engageable from
the interface. It is a file written to disk, so **it survives a crash or a
restart** — the system does not come back up forgetful. Clearing it is a
separate, explicit, recorded act by the operator. The check is written so that
anything other than a positive confirmation that the stop is absent counts as
"stopped": a permissions error or a disk fault reads as halted, never as clear.

**Step 12 — Read the results and export the proof.** Findings are shown as facts
or leads, and the interface derives that distinction only from whether the
system's own test actually fired. When you need to hand results to someone else,
two exports exist: a proof bundle that a third party can check with no part of
this system installed, and a single self-contained archive containing the human
reports, the machine-readable exports, the proof bundle, the scrubbed activity
log, the signed record chain and a list of checksums. The archive is honestly
labelled "signed" or "unsigned". Independent checking is covered in its own
chapter.

### 2.7 Keeping it running: backup, restore, upgrade and removal

An operations team needs answers to four questions that no demonstration ever
covers. One of them — restoring — carries a warning that is specific to this
system and does not apply to ordinary software. It is set out under *Restore*
below, and anyone responsible for the deployment should read it before they need
it rather than during an incident.

#### What lives where, so you know what to protect

The installation puts things in five places, and only two of them contain
anything you cannot simply rebuild:

| Location | What is in it | Rebuildable? |
|---|---|---|
| The sovereign home directory (`~/.sigil` by default) | The owner keys, the sealed key store, the signed record chain of everything the assistant half has done, the anti-rollback floor file, the configuration, and the cached memory | **No.** This is the irreplaceable part. |
| The working directory inside the installation (`.vigil-live`) | The offensive half's own signing identities, its signed record chain, its sessions, its usage ledger, the local knowledge graph, and the interface state | **No.** |
| The engagement folders (one folder per engagement, under a `targets` directory) | Each engagement's signed charter, its threat model and attack tree, the collected evidence, the findings, the notes and the reports | **No.** |
| The two built software environments and the compiled component | The installed software itself | **Yes** — rebuilt by re-running the setup script. |
| The optional container services | The memory database and the knowledge graph | **Yes.** The knowledge graph is never a source of truth: it is a rebuilt view, and replaying the signed records twice produces an identical graph. The memory database holds searchable copies of material that came from those same records. |

#### Backup

There is a real, purpose-built backup command on the sovereign half, and it is
worth describing precisely, because the way it is built answers several security
questions at once.

It produces a single **portable, passphrase-encrypted file** containing the signed
record chain (its segments, its index, its signed head, its floor file and its
security manifest), the owner's public key, and — deliberately — the owner's
**private** key and the key that encrypts the record contents. It exists because
the ordinary at-rest protection ties those keys to *this machine's* security chip:
that is the right protection day to day, but it means a dead disk would otherwise
take the entire audit history with it. The backup is the disaster-recovery route
onto **new** hardware, where the old machine's chip is gone.

Its integrity is layered, and the order matters:

- The whole file is encrypted and authenticated under a key derived from a
  passphrase **you** choose.
- Inside it, a manifest listing a checksum of every packaged file is signed by the
  owner key.
- On restore, a wrong passphrase, or any tampering with the encrypted bytes, fails
  to decrypt, or fails the manifest signature, or fails a per-file checksum —
  **before a single file is written**.
- After the files are written into a fresh, empty home directory, the restored
  record chain is re-checked for internal consistency, and the command refuses to
  report success on an inconsistent one.

Two honest points the code states about itself. First, restoring does **not**
re-check the owner's signature on the record chain's head; that check is tied to a
running instance's own configuration, so the documented next step is to run the
verification command against the restored directory. (Against someone who already
holds the passphrase this adds nothing anyway — the owner private key is *inside*
the backup, so the passphrase is the root of trust here.) Second, **the passphrase
is never stored anywhere.** Lose it and the backup is unrecoverable, by design.
That is the off-box confidentiality guarantee, and it is also a real operational
risk your key-management policy must cover.

For the parts the command does not cover — the offensive working directory, the
engagement folders and their evidence — an ordinary encrypted file backup is the
answer. There is no separate purpose-built command for those, and this chapter
will not imply one.

#### Restore — and one warning that is specific to this system

**Read this before restoring anything.** Several parts of the system keep a
durable "floor": a small file recording how far the signed record chain has got.
Its purpose is to make rolling the system backwards *detectable*, which is
precisely what an attacker who wanted to erase a record would try to do. The floor
refuses to move down. It is what makes a truncated or replayed history fail rather
than pass silently.

The operational consequence is easy to miss and expensive to discover during an
incident: **restoring an older copy over a newer state is not a neutral act.** A
naive restore — putting last week's directory back on top of this week's — can
present the system with a state smaller than the floor it has already recorded,
and the honest, deliberate response is refusal, not a shrug. Restore into a
**fresh, empty** home directory, which is what the restore command requires, and
verify before you cut over. Treat a restore as a planned change with a
verification step, not as a routine file copy.

#### Upgrade

The setup script is written to be re-runnable: every step checks for work already
done, and re-running it where nothing has changed does nothing. So the ordinary
upgrade is: take the new version of the code, run the setup script again, and run
the health check. The script rebuilds the two software environments and the
compiled component, leaves an existing configuration file in place rather than
overwriting it, and re-runs its own smoke tests — including the test that proves
the two halves of the system are still properly separated.

Two upgrade notes that are real and specific:

- **The signed record chain has a one-way storage migration.** Older installations
  keep the record chain as one growing file; newer ones keep it as numbered
  segments with an index. There is an explicit migration command, it is one-way,
  and it reports honestly when the work has already been done. A companion command
  performs a backup, the migration, and a compaction in one go.
- **The dependency lists are specific to one version of Python.** Regenerating
  them under a different version produces a different result. This matters to
  whoever maintains the deployment, not to a daily operator.

There is no automatic self-update, no update server, and nothing that phones home
to check a version. Upgrading is something your team does deliberately.

#### Removal

There is **no uninstall command for the system as a whole**, and this chapter will
not pretend otherwise. (There is a narrow removal command for one optional
integration: if you asked the assistant half to watch one of your own code
repositories, a command removes only its own block from that repository's
settings and leaves everything else alone. That is not a system uninstaller.)

Removal is manual, and it is manual because the system deliberately never installs
itself into shared, system-wide locations. What a complete removal means in
practice:

1. Stop the running interface, and disable any scheduled background services you
   enabled.
2. Delete the two small launcher shortcuts placed in your own account's local
   programme folder.
3. Remove the scheduled service definitions you copied into your own account's
   service folder, if you installed any.
4. Stop and remove the optional container services and their stored data.
5. Delete the sovereign home directory, the installation directory (which contains
   the working directory and the engagement folders), and any backups you made.

Steps 1 to 4 remove the software. **Step 5 destroys evidence, findings and the
signed record chain permanently**, and on a machine with a security chip the
sealed keys become unrecoverable once the sealed store is gone. Do it only when
you are certain, and take a backup first if there is any doubt. Nothing about the
installation is registered anywhere else on the machine, so once these five things
are gone, nothing of the system remains.

### 2.8 What is deliberately not automatic

Some things cannot be reached by pressing one button, on purpose.

- **Opening a code-fix pull request.** This is the only destructive action wired
  today, and every part of it is opt-in. With all switches off, the system merely
  proposes a fix and changes nothing. Applying the fix happens in a **throwaway
  copy** of the code; your working files are never touched. Opening the pull
  request is off by default and requires *all* of: a signed authorisation, a
  trust anchor, at least one mandatory signer including the owner, a durable
  single-use ledger, and a source-code-host token. The finding itself must be
  provenance-grounded — either a signed sealed record or one rebuilt from the
  signed history after an integrity audit. **A plain file of findings is never
  accepted.**
- **Multi-person authorisation for destruction.** The highest-consequence gate
  requires a threshold of distinct authorised signers *and* a mandatory owner.
  The owner requirement is fixed at deployment time rather than named per
  request, precisely because the worker process is itself a registered signer and
  could otherwise nominate itself.
- **Installing software.** As set out earlier in this chapter, two explicit human consents are
  required in the interface: the system first replies "needs consent" and shows
  the exact command, and only a second, deliberate press runs it.

### 2.9 What leaves your organisation, and what stays

This deserves to be stated without hedging.

**What always stays on your machine**

- The evidence collected during an operation.
- The findings, the proofs and the signed record chain.
- All keys and credentials, sealed at rest when a security chip is present.
- The activity history and the memory of past operations.
- All of the deterministic machinery: the fixed tests, the signing, the
  verification and the offline checkers. These need no outside service at all.
- The internal telemetry pipeline. If you enable it, its only permitted
  destination is the local machine; a non-local destination causes the exporter
  to refuse before anything is sent. Every field is scrubbed for secrets twice —
  once when the record is created and again at the moment of export — and the
  free-text fields are scrubbed at that boundary too.
- The knowledge graph, if you run one on your own infrastructure. It holds no
  secret and grants no permission; it is a rebuildable projection of the signed
  history.

**What leaves, only when you enable it**

1. **Prompts to a cloud AI provider.** If you configure a commercial AI service,
   the text the system asks it to reason about goes to that provider. This is the
   single largest data-egress consideration and the system addresses it directly
   with a four-rung **sovereignty ladder** that limits which providers may be
   chosen at all:

   | Setting | What it permits | What it costs you |
   |---|---|---|
   | Air-gapped | Only AI that runs on your own hardware. Cloud providers are refused outright. | Highest sovereignty; lowest reasoning quality. |
   | Sovereign cloud | Your own hardware, plus cloud AI with a regional/jurisdictional restriction (Amazon Bedrock, Google Vertex, Mistral). Direct consumer AI accounts are refused. | Frontier reasoning quality with data-residency guarantees. |
   | Trusted cloud | Adds enterprise and zero-data-retention arrangements. Requires an explicit operator attestation. | Requires a contract with the provider. |
   | Permissive | Anything. The development default. | No policy enforcement. |

   There is an important honesty note here, written into the code itself:
   zero-data-retention enrolment is **an organisational contract with the
   provider, not a per-request flag.** The system has no programmatic way to
   verify that a given key belongs to a zero-retention account. Setting that
   option is therefore an *operator attestation*, and the code says so. A
   government reader should treat it as a procurement question, not a technical
   guarantee.

   If you do not want prompts to leave at all, three keyless local options exist
   (a locally running model server, any self-hosted service that speaks the
   common interface, or a local session), and the system also has a fallback that
   uses no live AI at all and is explicit that its reasoning quality is bounded.

2. **Traffic to the target you are testing.** By definition. It is confined to the
   signed scope, and the permanently forbidden address ranges are unreachable no
   matter what the charter says.

3. **Queries to four public look-up services**, if you switch on live background
   research: a public DNS resolver, a certificate transparency log, a domain
   registration directory, and a network-numbering statistics service. These are
   queried *about* the target; they are never the target. The connection is
   restricted to exactly those four hosts and cannot overlap with the target's
   own scope. Responses can be saved locally so that subsequent runs can replay
   them offline.

4. **Calls to your cloud provider**, if you supply read-only cloud credentials —
   including a small "who am I?" call each time you press "test key".

5. **A proposed set of changes, and a pull request, to your source-code host**, if
   and only if you complete the deliberately difficult multi-signature ceremony
   described above. The changes are pushed as a separate, clearly-named line of
   work — never onto your main copy — and a human on your team must approve them.

6. **A short health check to each key's provider** when you press "Test". These
   are minimal, have no side effects, and **never send the secret's value
   anywhere except to its own provider for validation**. The cached result is
   stored in a value-free file.

7. **Polling your own call-back relay**, if you are running one for a remote
   engagement. The system connects to the relay host you named in the charter to
   ask "has anything called back?", carrying the shared secret in a request
   header. The relay is your infrastructure, on a host you own; no third party is
   involved. The relay itself sends nothing outward beyond the minimum reply
   needed to let the triggering request finish cleanly.

8. **Anything you deliberately publish.** Two items are meant to be shared: the
   short fingerprint of your trust anchor, which recipients need in order to
   check your proofs independently, and any proof bundle or archive you choose to
   send. A separate, operator-only command can publish curated knowledge notes to
   a code host; it runs a secret scan first and refuses to commit on a hit — and
   the code is explicit that this scan is a safety net, not a guarantee, and that
   the operator is still expected to redact.

**Nothing else leaves.** There is no measurement data sent back to a vendor, and
no cloud control plane. There is also no licence check-in: the licensing
obligation described in section 2.1 is a legal agreement, not something the
software phones home to verify, so a licensed deployment can run entirely
disconnected. The system is run entirely by the organisation that installs it.

### 2.10 Where the software itself comes from — build and release safeguards

An organisation does not only need to know what the system does once it is
running. It needs to know that the software it installed is the software that was
reviewed. That is the *supply chain*, and it is a real attack surface: an
adversary who can change what your build pulls in never has to touch your
repository at all.

Four safeguards address this. All four are now part of the released version of the
software and run in the automated build. Each is described here as what it is,
with its current state stated plainly at the end of the section.

**1. Every third-party component pinned by fingerprint, not just by version.**
A version number is a label; two different files can carry the same label. The
build therefore records a cryptographic fingerprint of the exact file for every
component, and installation refuses the entire set if any single file does not
match. There are two such lists, one for each of the two isolated halves of the
system, because those halves must never share an interpreter and so cannot share
a resolution. The specification for the sovereign half also carries the rule that
keeps the halves apart in writing: nothing in it may pull in the offensive
engine, and that absence is what makes the offence-free guarantee hold by
construction rather than by good intentions.

**2. Container base images pinned to content, not to a moving label.** A label
such as "Python 3.13, slim" is a *pointer*, not a thing. It means "whatever the
registry happens to serve when you download." If that pointer is moved — by the
upstream maintainer or by an attacker — what ships changes silently, in the
project's own words "with no diff, no review and no signal." Every base image in
the repository is now pinned to a content fingerprint, which the container
software verifies or the download fails.

A small dedicated checker enforces this in three deliberately different modes: an
offline test, a build-blocking command, and a **networked drift report** that
re-checks whether the upstream label has moved on. The drift report is
**advisory and never blocks a change**, on explicitly stated reasoning: upstream
retagging is not the fault of the change being reviewed, "so it must not turn a
contributor's build red." That is a considered distinction between a gate and a
report, and it is the difference between a control that survives and one that
gets switched off. Exemptions are written as rules rather than as holes: an empty
base has nothing to pin, and images built from this repository have no upstream
fingerprint because their origin is the source tree itself. Two floating
"latest"-style settings were removed outright, because a moving pointer hidden
behind a configuration variable "is the exact drift this pinning exists to stop."

**3. A software bill of materials.** This is an itemised inventory, in a standard
published format, of every component that goes into the build — the equivalent of
an ingredients list. It is generated from the pinned list and then **cross-checked
against that list component by component**, so the inventory cannot quietly
disagree with what actually installs. It is produced and published as an output
of every build, where a customer or an auditor can take it.

**4. A vulnerability gate that blocks on the most severe class.** Every build
scans the whole repository against a public vulnerability database. The threshold
is deliberate and written down: **a CRITICAL finding blocks the change; a HIGH
finding is reported in full but does not block.** The reasoning is stated
directly in the file: "A gate whose allow-list has to grow without limit to stay
green is theatre; a gate that blocks on CRITICAL and reports HIGH keeps meaning
something." Every exception must carry a written justification, and an automated
test enforces that rule rather than trusting reviewers to notice.

Two further details show the standard being applied to the safeguards themselves.
The scanner is installed pinned both by version *and* by the fingerprint of its
download, because fetching a security scanner from a moving address "would be its
own supply-chain hole." And the build tools — the pinning tool, the inventory
generator, the scanner — are deliberately **not** shipped as part of the product,
because adding them to what gets deployed "expands the deployed attack surface
without expanding the runtime feature set."

The static half of these checks runs with no network at all, so an organisation
in a restricted environment can still verify for itself that the work was done.

**Current state, stated honestly.** An earlier version of this chapter reported
this work as written and working but **not yet folded into the released version of
the software** — in the same way that a finished chapter is not yet a published
book. That is no longer the position. **All of it has now been folded in and is
part of the released version.** Present and working in the released software:

- The two fingerprint-bearing component lists themselves, one for each half of the
  system, both committed and both carrying a fingerprint for every single entry.
- The check that the two halves really do install from those lists — proven not by
  inspecting them but by performing a clean installation that refuses anything
  unfingerprinted, because a list full of fingerprints that the installer rejects
  is a document, not a control.
- The image-pinning checker, with its offline test, its build-blocking command and
  its advisory report on whether an upstream label has moved.
- The inventory generation and its component-by-component cross-check against the
  lists.
- The vulnerability gate that blocks on the most severe class, together with its
  negative control (described below) and a written justification requirement for
  every exception.
- The written policy document setting all of this out, which a reviewer can read
  directly.

Two details from that document deserve a government reader's attention because
they show the standard being turned on the safeguards themselves.

*The scanner is proved able to fail.* The gate currently passes with an empty
exception list, because the code base has no findings of the most severe class.
That is the right outcome — and it is also indistinguishable from a scanner
mis-configured into reporting nothing at all: a mistyped setting, a severity name
that matches no severity, an analyser that found no files to read. So the build
runs a **deliberate failure test immediately before the real gate**: the exact
blocking configuration, pointed at a sample of known-severe components, which
*must* fail. If it passes, the build stops with a message to the effect that the
gate below cannot fail, so its green tick means nothing.

*A setting was found to be hollow and fixed.* The scanner matches files by name,
and by default it silently skipped both of the fingerprint-bearing lists — that is
to say, it skipped exactly the two files this work exists to produce. The
configuration now names them explicitly. A gate that does not scan what the change
adds is hollow.

There is one deliberate omission a reader should not misread. The itemised
inventory is **generated on every build and published as a downloadable output,
not committed into the source code**. Two are produced, one for each half of the
system, and each is cross-checked against its own fingerprint-bearing list before
the build is allowed to pass. The reasoning is stated: the inventory is derived
from that list, which is the committed source of truth, and a file regenerated on
every run and committed each time is noise that reviewers learn to scroll past. So
its absence from the source tree is a decision, not a gap.

**One loose end, named here rather than left for a reader to find.** A placeholder
inventory file from *before* this work still sits in the source tree, in the
offensive engine's own folder. It is not what the build produces. It carries its
own marker saying it is a scaffold, and a placeholder date written as all zeroes,
and an older security document elsewhere in the repository still points a reader at
it as though it were the real thing. Removing that file and correcting that older
document is the one piece of this work still outstanding on the day this chapter
was written. Until it is done, the position is: **the file in the source tree that
is named like an inventory is not an inventory of the shipped software and must not
be cited as one.** The real inventories are the two the build generates and
publishes. This is housekeeping, not a missing safeguard — every one of the four
controls above is in place and running.

That leads to a final note about how the earlier gaps were labelled, because it
says something about the culture a buyer is purchasing. Before this work landed,
the placeholder files **said so about themselves**: the earlier dependency file
stated in its own header that it was "intentionally NOT a real lock", and the
placeholder inventory carries a scaffold marker and a placeholder date to this day.
They were honest about their own state; the error would be a *reader* mistaking
their presence for completion. For the dependency lists that risk is now gone,
because the real, fingerprint-bearing lists have replaced them. For the one
leftover inventory file the marker is still doing its job — and this chapter states
the position plainly rather than relying on a marker inside a file to do it.

One thing must not be confused with another, because they are the same subject
matter pointed in opposite directions. The system can read a **target's**
component list against stored vulnerability data and produce a proven finding
about that target; that is a product feature, described earlier in this chapter.
The four safeguards above are about securing **this system's own** build.

### 2.11 Honest status: built, but not yet fired at a live outside system

This project maintains a written doctrine that an overstated claim is corrected by
building the capability up, never by quietly softening the words. In that spirit,
the following are genuinely built and tested but have **not** been exercised
against a live third-party system, and must never be presented as completed field
deployments.

**The cloud and Kubernetes capabilities deserve a paragraph rather than a table
row, because the position is precise and easy to get wrong in either direction.**

Six confirmations are complete and part of the released software, wired end to
end. In plain terms, each proves that something was actually *achieved*, not
merely that a setting looked wrong:

1. A credential was taken from a cloud machine's own credential service — and that
   credential really worked.
2. A secret found lying exposed is a **currently working** credential, not just a
   string that looks like one.
3. One Google Cloud identity can act as another.
4. An identity's permissions let it give itself more power than it started with.
5. On a container platform, an anonymous caller — anyone at all, with no login — is
   attached to a dangerous administrative role.
6. On the same platform, a role genuinely grants dangerous powers, proven by
   reading the role's actual rules rather than trusting its name.

The four **cloud** confirmations — numbers 1 to 4 above — are proven **offline,
against recorded sample data**. (Recorded sample data means exactly what it sounds
like: a saved, realistic copy of what a cloud account would have replied, kept on
file so the test can be run and re-run without touching anybody's real account. It
is the software equivalent of a laboratory running a known reference sample through
its instrument to prove the instrument reads correctly.) The two **Kubernetes**
confirmations — numbers 5 and 6 — are no longer in that position. They are proven
against a real single-node cluster, k3s version 1.31.5, running in a container on
the machine's own internal address, which the system stands up, owns and destroys
itself. It plants known-dangerous and known-benign access rules in that cluster,
captures what the real Kubernetes interface returns, and puts those bytes through
the ordinary path: checker, admission, certificate, offline re-verification. The
dangerous binding is confirmed and its certificate re-verifies with no network; the
benign ones in the same cluster stay leads, including the namespace's own default
identity bound to the built-in `admin` role, whose real rules do grant secret reads
— the commonest legitimate arrangement in Kubernetes, and the one a careless
detector would wrongly call critical. For all six, the detection logic, the evidence
handling, the certificates and the safety gates are built and proven.

**What remains deferred, for the four cloud confirmations, is one thing only:
pointing them at a live third-party cloud account.** That waits on the customer
supplying their own cloud credentials, and it is deferred by design — a credential
is a thing only the account owner can issue, and the system is deliberately built
not to obtain one any other way. For the two Kubernetes confirmations nothing
external is waited on; what that run does not cover is a scope-gated capability
that discovers access rules across a whole cluster, and a managed provider's
control plane (Amazon EKS, Google GKE, Azure AKS).

The accurate sentence, which should be used wherever this comes up, is: *built and
gated throughout; the two Kubernetes confirmations proven against a real cluster
the system creates itself, the four cloud ones proven offline, their first use
against a real, live cloud account awaiting the customer's own credentials, by
design.* Calling these capabilities unfinished would understate the system. Calling
the cloud ones proven in customer clouds would overstate it. Both errors mislead,
in opposite directions.

Five safety properties are shared by all six, and they answer the obvious concern
about letting an automated system anywhere near a cloud credential:

1. **They cannot fire on their own.** None of these tests is reachable by an
   ordinary scan or engagement. Each runs only when explicitly called. An
   autonomous loop cannot wander into using a cloud credential.
2. **There is exactly one sanctioned route to a proven finding**, through a
   central admission step. No individual module is permitted to issue a
   certificate itself.
3. **No live secret is ever kept.** The credential is checked and fingerprinted in
   memory and then discarded. What is retained is a redacted structural record,
   the fingerprint, and non-secret provenance — and the certificate still
   re-checks offline afterwards. For the Kubernetes tests the retained record
   carries only permission metadata, never the token used to read the cluster.
4. **Authorisation and scope are checked before any network activity.** An
   unauthorised or out-of-scope call refuses before a single packet leaves.
5. **The connection must prove itself.** The network layer must report which
   address it actually reached, whether encryption was verified, and whether any
   proxy or redirect intervened; the judging test *requires* a verified encrypted
   connection with no proxy and no redirect. A hand-written record can never
   become a proven finding, because the evidence of where the calls actually went
   originates only in the live runner.

With that stated, the remaining honest deferrals are:

| Capability | Status | What is blocking live use |
|---|---|---|
| The six cloud and Kubernetes exploitation confirmations | **In the released software.** The two Kubernetes ones are **proven against a real cluster** the system stands up, owns and destroys; the four cloud ones are **proven offline against recorded sample data** | For the four cloud confirmations, real-world use against a live third-party cloud account remains. For the two Kubernetes ones, nothing external is blocking: what that run does not cover is enumeration of bindings across a cluster and a managed provider's control plane (EKS, GKE, AKS). |
| AI red-teaming tools as a source of proven facts | Built, not yet run live | Those tools are absent from the current environment and there is no network access to install them. The code explicitly does not mint facts from them. |
| Running an external tool inside the pinned-network container | Built, not yet run live | Needs container software, the isolated network, and a tool image present. |
| Speaking live to an external tool-server | The manifest and validation layer are built; the live client is a pending piece | Described in the code as the one remaining seam. |
| Opening an automatic fix pull request | Built, not yet run live | The operator must generate the multi-signature keys and supply a source-code-host token. |
| Live cloud and Kubernetes **posture** checks (the read-only configuration review, distinct from the six confirmations above) | Built, awaiting credentials | Requires operator-supplied read-only credentials. Each is validated by a live probe when present. |
| Supply-chain hardening of this system's own build | **Complete and in the released software** — no longer deferred | Nothing external. All four safeguards, both component lists and the written policy are in the released version. One housekeeping item remains — a leftover placeholder inventory file in the source tree. Section 2.10 states it in full. |
| An externally hosted graph database | Client built; deployment deferred | The embedded, file-based graph store is built and works. |
| Hardware-backed confidential-computing attestation | Scaffold only; the stubs deliberately fail | Requires confidential-computing hardware. A software-backed equivalent works today and honestly reports that it is not hardware-backed. |
| General automatic repair of compiled programs | Scaffold only; the function deliberately fails | Research-gated. A narrow, crash-confirmed repair path *is* built. |
| A next-generation agent body | Interface only | Needs an external toolkit and a live container. |
| Anchoring records to a public blockchain timestamp | Deferred | Needs a live timestamping server. |
| An independently operated set of witnesses | The protocol and a deployable witness service work; genuine independence is a deployment assumption | Distinct keys are not the same as distinct organisations. The system's own trust document says so and calls a producer-held quorum "theatre". |
| A published field record across many diverse real targets | The mechanism is built; the record itself is not | Access and permission, not engineering. |

---

## A one-page checklist

**Before anything else — the licence**

- Decide which licence applies to you. Non-government, non-commercial use is free
  under the source-available licence. **Any government or public-sector use — and
  any commercial or production use — requires a commercial licence agreed with the
  copyright holder.** See section 2.1. This is a conversation to start early, not
  a formality to tidy up later.

**Minimum to install and explore, with nothing bought**

- A Linux machine with Python 3.12 or 3.13 and the Rust toolchain.
- Run the setup script; answer "yes" when it offers to install the security tools.
- Run the health check.
- Bring up the interface and open the printed local address.

**To run a real operation against a system you own**

- A written charter naming the in-scope systems, with your attestation, limits
  and stop conditions. (The intake step can draft one for you from a web address;
  a human still reads, edits and signs it.)
- A signed authority minted from that charter on a trusted machine that holds the
  owner key.
- The six required security tools installed (the Tools screen shows you).
- An approval authority minted, so queued actions can be signed one at a time.
- **Test accounts on the target application**, if any of its interesting surface
  is behind a login — two identities at different privilege levels if you want
  the access-control tests, plus the record references each one owns.
- **A call-back relay you host, on a host named in the charter**, if the target is
  not running on the same machine as the tester. Without it, the four blind
  checks and every other call-back-confirmed weakness are skipped, not guessed.
- Optionally, an AI provider key — chosen at the sovereignty level your
  organisation's data-handling policy requires.

**If your organisation already runs other security tools — you keep them**

- Nothing needs to be switched off. The system can read the report another tool
  produced, without running that tool at all: eight input formats are accepted, and
  they are listed in section 1.6.
- What comes in that way arrives as a **lead**, labelled with where it came from,
  and is re-proved by the system's own test wherever one applies. A claim that
  cannot be re-proved stays a labelled lead and says so. Nothing is recorded as a
  proven finding on the strength of another tool's word.
- Importing the same report twice changes nothing, so a count cannot be inflated by
  running an import again.

**Before you test your own government estate — read this**

- The system contains a permanent block on a whole category of internet address:
  government, military, educational and intergovernmental domains. It is
  deliberately not switchable. As written it would refuse to test a `.gov` or
  `.mil` host — which is to say, an agency's own estate.
- The chapters that cover this also report, accurately, that no live call site for
  that block could be found on the current operating path, so a reader should not
  assume it is currently doing anything.
- Either way, **an agency intending to assess its own estate by domain name must
  have this addressed deliberately and explicitly, and must not work around it
  quietly.** Chapter 8 is where this is set out. Raise it in the first technical
  conversation, not the last.

**Strongly recommended before production use**

- A security chip, so keys are encrypted at rest.
- Remote access through an encrypted tunnel and your own reverse proxy, never a
  public listener.
- Your trust-anchor fingerprint published through a separate channel, so
  recipients can check your proofs independently.
- **A backup routine, and a rehearsed restore.** Use the built-in
  passphrase-encrypted backup for the assistant half's keys and signed record
  chain, and an ordinary encrypted file backup for the offensive working directory
  and the engagement folders. Store the backup passphrase where your key-management
  policy says such things live — it is never stored by the software and cannot be
  recovered. Rehearse a restore into a fresh, empty directory before you need one,
  and read the warning in section 2.7 about restoring an older state over a newer
  one.
- **A decision on whether this is a governed deployment.** Provisioning the trust
  root that switches on capability entitlements is an installation-time choice, and
  it is the mechanism that limits what a stolen copy of the software can do. See
  section 2.6, step 1.

**Required only for specific extras**

- Container software — for the isolated agent, the container-based tool runner
  and the optional services.
- Read-only cloud credentials — for cloud and Kubernetes posture checks, and for
  the first real use of the four cloud confirmations.
- A source-code-host token plus multi-signature keys — for automatic fix pull
  requests.
- A graph database — for the visual knowledge map.
- A host you own, reachable from the target — for the call-back relay.

**Five things only your organisation can supply**

These are not software gaps. Each is something the system is structurally unable
to provide for itself, and a procurement conversation should treat them as
inputs, not as missing features.

| What | Why the system cannot supply it |
|---|---|
| Written authorisation to test a system | Only the system's owner can grant it. The charter is where it is recorded, and nothing runs without one. |
| Cloud credentials for live cloud testing | Only the account owner can issue a credential, and the system is designed not to obtain one any other way. This is the single remaining blocker for the first real use of the four cloud confirmations. The two Kubernetes confirmations do not need it — the system stands up a cluster of its own. |
| Genuinely separate holders of the multi-signature keys | The code can require several distinct keys. It cannot verify that different people hold them. |
| A security chip, or a virtual equivalent | Without it, keys sit unencrypted on disk. Acceptable on a trusted single-user machine, inadequate on a shared or hosted one. Setup warns loudly rather than degrading silently. |
| Independently operated witnesses | The protocol and a deployable witness service are built and working. Independence is a deployment arrangement, and the project's own trust document says plainly that distinct keys are not distinct operators. |

---

## The one thing to take away

The two halves of this chapter meet at the same point. The tool list is short. Two
of thirty-three catalogued tools may contribute to a proven finding. The technical
requirements are modest, and nothing bought from another software vendor is
strictly required to start — though a government reader does need a commercial
licence, and that is the first thing to arrange.

Adding tools, keys and credentials widens what the system can *look at*. None of
it widens what the system is willing to *claim*. That distinction is the whole
design, and it is why the two lists in this chapter are the length they are.
