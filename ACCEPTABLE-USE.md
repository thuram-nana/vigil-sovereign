# ACCEPTABLE USE

VIGIL is autonomous offensive-security tooling. It finds real vulnerabilities in real
systems and, where authorised, proves them by exploiting them. Pointed at a system whose
owner did not agree, that is a crime in most jurisdictions — and the tool cannot tell the
difference. You can.

This policy is **binding on everyone who uses VIGIL**, under either branch of the dual
licence ([`LICENSING.md`](LICENSING.md)). It is not advice and it is not optional. It
states one rule, the evidence that rule demands, the technical controls that back it, and
what happens when it is broken.

> This is a repository policy, not legal advice, and it is not a substitute for counsel in
> your jurisdiction or your target's. Where it and the licence texts address the same
> subject, the licence texts control.

---

## 1. The rule

> **Test only what you own, or what you hold current written authorization to test —
> and only within the limits that authorization sets.**

There is no second rule that softens this. "Just checking", "it was already exposed",
"it's a test environment", "the bug bounty probably covers it", and "I was going to ask
afterwards" are not authorization. Neither is the fact that a host answered.

Authorization has to be: **written**, from someone with **authority to grant it** for that
system, **current** at the moment you test, and **specific** about what is in scope, what
is off limits, and when the window opens and closes.

## 2. What you must have before the first packet

VIGIL's own entry gate is the engagement charter, and it is not decorative.

| Requirement | Where it lives |
|---|---|
| A charter for the target, signed by the person attesting ownership or authority | `targets/<slug>/charter.md`, from `engine/crucible/framework/templates/charter.md` § 1 |
| An explicit in-scope list — hosts, surfaces, and (for cloud) the named account / project / subscription, never a shared endpoint | charter § 2 and § 2b |
| The hard limits, written down before you start | charter § 4 |

The template's § 4 is the floor the project expects every engagement to keep, and it is
worth reading as policy rather than boilerplate: no DoS or resource exhaustion; no
real-user contact; no exfiltration of real user data beyond the minimum needed to
demonstrate impact; no persistence on production beyond proof; **no third-party attack**;
no proxy chains, Tor, or rotating residential IPs unless the EMULATE posture is explicitly
authorised; no bulk deletion.

An unsigned charter is not a formality you can skip: `require_charter_signed` refuses, and
the refusal is deliberately hard to fake — a blank signature line cannot slurp the next
line as a name (`engine/crucible/framework/v2/common/ethics.py:129`).

## 3. Prohibited uses

You may not use VIGIL, or anything built from it:

1. **Against a third party.** Any system, network, account, application, or dataset you do
   not own and are not authorised to test. Including systems merely *reachable* from an
   in-scope host — a discovered subdomain, a linked API, a shared cloud endpoint, a
   customer of your customer.
2. **To obtain, keep, or extend unauthorized access.** Including credential capture used
   beyond proving impact, persistence left behind, or access retained after the
   authorization window closes.
3. **To build, test, tune, package, or deliver malware, ransomware, wipers, botnets,
   command-and-control infrastructure, or denial-of-service capability** — against anyone,
   including a system you own. This is a prohibited *purpose*, not only a prohibited target.
4. **To develop or validate evasion of another party's defences** — anti-detection tooling,
   WAF/EDR bypass libraries, log tampering, or anything whose product is "the defender does
   not see it". See § 5.
5. **To surveil, profile, or target individuals**, or to process personal data beyond what
   the engagement's authorization and applicable law permit.
6. **To extort, blackmail, or pressure** — including using a finding, an exfiltrated file,
   or a signed certificate as leverage.
7. **To circumvent the controls in § 4** — editing a charter you were not authorised to
   edit, forging a signature, disabling the protected-domain floor to reach a class the
   floor exists to remove, or patching a gate out to reach something it refused.
8. **Where a licence forbids it** — commercial, production, or any government / public-sector
   use without a Commercial Licence (`LICENSE` Supplemental Term; [`LICENSING.md`](LICENSING.md)).

## 4. The technical controls that enforce this — and their honest limits

VIGIL implements this policy in code, not only in prose. It also does not pretend the code
is sufficient. Each control below is real; each has a stated limit.

| Control | What it does | What it does not do |
|---|---|---|
| **Charter signature gate** — `engine/crucible/framework/v2/common/ethics.py:129` | Refuses to run against a target whose charter carries no real signature | Cannot verify the signature is *true*. Signing a charter for a system you do not own is a lie told to a text file, and it is on you |
| **Scope gate** — `engine/crucible/framework/v2/agents/scope_gate.py`, `ethics.require_in_scope` (`ethics.py:283`) | Five ordered checks before any HTTP action; a refused action never reaches the wire. The only place charter/scope gating happens for `HttpExecutor` | Governs the paths that route through it. It cannot govern a tool you run by hand outside VIGIL |
| **Protected-domain floor** — `packages/core/vigil_core/vigil_core/hard_guardrail.py` | A deterministic, network-free, LLM-free denylist for government / military / educational / intergovernmental domains, evaluated **before** the charter or any gate, with Unicode dot-homoglyph folding so `un。org` cannot slip through. Fail-safe: unset or junk toggle ⇒ enabled | Can only deny — it never authorises anything. An owner can turn it off via a signed config toggle; doing so to reach a protected class is a breach of this policy |
| **Egress gateway** — `gateway/` (`nftables.py` L3/L4 deny-default, `proxy.py` L7 per-connection) | The offense sandbox reaches the network **only** through the gateway: deny-default firewall, charter scope re-used not reinvented (`scope_source.py`), one-shot DNS resolution with the validated IP pinned (rebinding-safe), and hard drops for metadata / link-local / reserved ranges including IPv4-mapped and IPv4-compatible IPv6 forms (`denylist.py`) | It is a *deployment*. It enforces what it is wired in front of. A VIGIL run outside that topology does not get it |
| **In-process egress guard** — `engine/crucible/framework/v2/agents/egress_guard.py:254-281` | The protected-domain floor runs **unconditionally**, including in permissive mode. Under a sovereign tier, host allowlist enforcement refuses everything not in the charter scope, LLM hosts, provisioned collector hosts, or explicit extras | Under the default `PERMISSIVE` tier the allowlist **logs but does not refuse** (line 265), and the guard is per-client-instance, not a global patch — the deployment is responsible for wiring it |
| **Kill switch, WARDEN gate, approval queue, RBAC admission** | Halting is honoured from any event; un-halting requires an owner signature. Higher-tier actions queue for owner approval instead of auto-firing | These constrain the tool. They do not constrain a human with the owner key |
| **Usage-attestation ledger** — `integration/vigil_integration/attestation/models.py:24-45` | Every run is recorded in an append-only hash-chained ledger binding OS login, git identity, hostname, and the operator key fingerprint. The ledger **refuses** a record with no human handle | It is evidence, not prevention. It makes anonymous use unsupported, not impossible |

**The honest summary.** These controls stop mistakes, drift, prompt injection, and a
misconfigured autonomous agent. They are defence in depth around an authorization decision
that a human makes, and they cannot make that decision for you. A determined operator with
the owner key can point VIGIL at anything. That is exactly why this policy exists and why
the ledger records who did it.

## 5. Correlatable by doctrine — VIGIL is not an evasion tool

VIGIL is built so the system owner can find your traffic in their own logs. That is a
design commitment, not an accident:

- **Identifying User-Agent.** Default postures send
  `OBSIDIAN/1.0 (authorized owner-test <date>)`, deliberately correlatable
  (`engine/crucible/framework/v2/agents/http_executor.py:82-115`).
- **Throttling by posture.** Fixed minimum inter-request delays per posture — TEST 0.2s,
  AUDIT 1.0s, EMULATE 5.0s with jitter (`http_executor.py:75-80`).
- **The one exception is charter-gated.** The EMULATE posture uses a realistic browser
  User-Agent string and the *slowest* rate profile. It applies only when the charter's § 7
  checkbox selects it; the parser defaults to TEST when no posture is checked or no charter
  exists (`http_executor.py:85-92, 105-116, 129`). EMULATE is still fully scope-gated by
  the same charter and scope checks as every other posture, and the charter's § 4 still bars
  proxy chains, Tor, and rotating residential IPs unless EMULATE was explicitly authorised.
  Stated precisely: the scope gate's posture-restriction step is presently a hook that adds
  **no** extra checks for EMULATE — the constraint on EMULATE today is the charter and the
  operator, not an extra code path (`scope_gate.py:181-186`).
- **The project refuses to build evasion.** The operating doctrine treats a WAF block as a
  positive control finding, not a challenge: "do not turn it into evasion theater"
  (`engine/crucible/CLAUDE.md:247-253`). The vendored third-party brain was reimplemented
  clean-room with a runtime `DriftError` guard that rejects any evasion, stealth, or
  IP-rotation knob (`docs/BRAIN-SLOT-INTEGRATION.md:19, 34`). In the defensive build stream,
  a change that adds evasion, payload, C2, or persistence capability is refused outright, and
  that refusal is explicitly not human-waivable within that stream
  (`engine/crucible/FORGE.md:27, 177`).

**Said honestly, because a policy that overstates its own tool is worthless:** VIGIL is an
offensive framework and it *does* carry post-exploitation, persistence, and
data-exfiltration-impact material (`engine/crucible/framework/playbooks/21-post-exploitation.md`,
`22-data-exfiltration-impact.md`). Those run only per the engagement's rules of engagement,
and the charter's hard limits still apply — no persistence on production beyond proof, removed
within the same session (charter § 4). What the project does not build is the capability to
*hide* that work from the system's own defenders.

If your goal is to not be seen, VIGIL is the wrong tool, and asking for it to become that
tool is out of scope for this project.

## 6. Two decisions the tool leaves to you

Both are documented behaviour, not defects. Both have consequences for someone who is not
you, so both belong in this policy.

**Model egress defaults to permissive.** The sovereignty tier governs which model backends
the engine may call. Unset, it resolves to `PERMISSIVE`
(`engine/crucible/framework/v2/kernel/sovereignty.py:195`), and the installer writes every
tier line **commented out** (`bootstrap.sh:326-336`). In that state, prompt content — which
can include target data and findings, which can include a third party's personal data — may
be sent to a commercial cloud model provider. If your engagement, your client contract, or
the law that reaches you does not permit that, set a tier before the first run, and note
that the tier does not cover the sovereign plane's own model calls (see
`engine/crucible/SECURITY.md` § 3.5 for the honest limits).

*Set* it by **exporting** `CRUCIBLE_SOVEREIGNTY_TIER` in the environment the process
inherits. The engine reads that variable from the process environment and from nowhere
else (`engine/crucible/framework/v2/kernel/sovereignty.py:183-195`): a tier stored only in
`~/.sigil/sigil.env` or on the UI Settings screen reaches an offense process only when
`vigil up` launched it — and only as of that start, since the runtime env is resolved once
at bring-up (`integration/vigil_integration/uiproxy.py:2104`), so a tier changed in Settings
while the UI is already running takes effect only on the next `vigil up`, not on a run already
launched from the UI. An offense process started any other way falls back to
`PERMISSIVE` **silently — fail-open**. `/PRIVACY.md` § 5.1a states each mechanism's scope
and where to read the tier actually in force.

**Evidence is retained unredacted.** `targets/<slug>/evidence/<action_id>/response.body`
holds full raw response bodies from the client's systems; only credential headers are
masked (`engine/crucible/framework/v2/agents/http_executor.py:744-752`,
`engine/crucible/framework/v2/common/redact.py:17-49`). That is deliberate — redacted
evidence cannot be re-verified — and it means the engagement directory is client data. Its
storage, transfer, retention, and destruction are your responsibility under your
engagement's terms.

## 7. Consequences

**Licence.** This policy is a condition of use. Under the PolyForm Noncommercial License
1.0.0 "Violations" clause, the first written notice of a violation gives you **32 days** to
come into full compliance and take practical steps to correct past violations; otherwise
**all your licences end immediately** (`LICENSE`). A commercial licence may impose stricter
or additional termination terms — read your signed agreement. Licence termination means you
must stop using VIGIL; it does not resolve anything else you did.

**Everything else.** Unauthorized access, interference, and interception are criminal
offences in most jurisdictions, and several of them reach across borders — see
`engine/crucible/DISCLAIMER.md` § 2. The maintainer does not control, monitor, or authorise
your use, provides no warranty, accepts no liability for it, and you agree to indemnify the
maintainer for it (`engine/crucible/DISCLAIMER.md` §§ 3-6). Making a tool available is not
authorization to attack anyone.

**Reporting misuse.** If you believe VIGIL is being used against systems whose owners did
not authorise it, contact `thuram@thuramnana.com`. To report a vulnerability *in VIGIL*,
follow [`SECURITY.md`](SECURITY.md) instead.

---

*Related:* [`LICENSING.md`](LICENSING.md) · [`LICENSE`](LICENSE) ·
[`TERMS.md`](TERMS.md) · [`EXPORT.md`](EXPORT.md) · [`PRIVACY.md`](PRIVACY.md) ·
[`engine/crucible/DISCLAIMER.md`](engine/crucible/DISCLAIMER.md) ·
[`engine/crucible/CLAUDE.md`](engine/crucible/CLAUDE.md) (the operating constitution).
