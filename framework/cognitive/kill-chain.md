# Kill chain

A kill chain is the sequence of actions an adversary takes from first
contact to objective. Mapping your engagement to a kill chain gives
you (a) a way to talk about *where in the attack* a given finding
sits, (b) a way to spot defensive gaps that aren't tied to a single
vulnerability, and (c) a structured framework for chaining bugs into
realistic exploit narratives.

This document uses a hybrid of the **Lockheed Martin Cyber Kill Chain**
(strategic, 7 phases) and **MITRE ATT&CK Enterprise** (tactical, 14+
tactics). The hybrid is what most modern red teams actually use.

---

## 1. The seven strategic phases

```
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objectives
```

Map each finding you discover to a phase. Findings that sit in late
phases (5–7) imply the adversary has already gotten through earlier
phases — but they may also represent independent paths an outsider
could take if they bypassed earlier defenses some other way.

For owner-test of a web app, most findings cluster in phases 1, 4, 7.
Phases 2–3 are mostly relevant for client-side delivery (phishing,
drive-by) which is usually out of scope.

---

## 2. MITRE ATT&CK tactics — the 14

ATT&CK tactics are *what an attacker is trying to accomplish at a
moment in time*. Useful for granular mapping.

| Tactic | What it means | Web-app relevance |
|--------|---------------|-------------------|
| **TA0043 Reconnaissance** | Gather info before attack | OSINT, subdomain enum, JS scraping |
| **TA0042 Resource Development** | Build / acquire resources | (Mostly out of scope for owner-test) |
| **TA0001 Initial Access** | Get foot in the door | Auth bypass, weak creds, exposed admin, public exploit |
| **TA0002 Execution** | Run code on a system | RCE via SSTI / deserialization / cmd-injection / file upload |
| **TA0003 Persistence** | Maintain access | Webshells, SSH keys, scheduled tasks, modified core files |
| **TA0004 Privilege Escalation** | Get higher privileges | Role escalation in app; OS-level escalation if shell achieved |
| **TA0005 Defense Evasion** | Avoid detection | Log tampering, AV/WAF bypass — observe but rarely emulate in owner-test |
| **TA0006 Credential Access** | Steal creds | DB dump, session hijack, JWT crack, hashes |
| **TA0007 Discovery** | Learn about environment | Endpoint enum, internal IP scanning, DB schema enum |
| **TA0008 Lateral Movement** | Move to new systems | SSRF to internal services, internal API auth bypass |
| **TA0009 Collection** | Gather data | DB queries via SQLi, IDOR enumeration, file system reads |
| **TA0011 Command and Control** | Communicate with comp'd hosts | Out-of-scope unless explicit authorized RT engagement |
| **TA0010 Exfiltration** | Steal data | DNS exfil from SQLi, HTTP exfil via SSRF, archive uploads |
| **TA0040 Impact** | Damage / disruption | Data deletion, money movement, defacement |

For each finding, tag it with the relevant tactic(s). This becomes
the "kill chain coverage" view of your work.

---

## 3. Mapping to the engagement

Most engagements proceed roughly like this kill-chain progression:

```
Stage 1 (charter)         ← out of band, not on the chain
Stage 2 (threat model)    ← not on the chain
Stage 3 (recon)           = TA0043 Reconnaissance
Stage 4 (mapping)         = TA0007 Discovery (parts), TA0043 (more)
Stage 5 (vuln-hunt)       = looking for entry points and pivots
Stage 6 (exploitation)    = TA0001 Initial Access
                            → TA0002 Execution
                            → TA0006 Credential Access
                            → TA0004 Privilege Escalation
Stage 7 (post-exploit)    = TA0008 Lateral / TA0009 Collection
                            (only with explicit authorization)
Stage 8 (reporting)       ← out of band
Stage 9 (validation)      ← out of band
```

The agent does not always pursue late-stage tactics — that's an
operator decision per the charter. Many owner-tests stop at proving
initial access for each vulnerability without actually post-
exploiting (because doing so on production is risky and unnecessary
to demonstrate the bug).

---

## 4. Chains, not lists

The most realistic adversary attack is not "single critical bug" —
it's a **chain** of medium-severity issues that together reach a
high-impact objective.

When you have multiple findings, ask:

- Does Finding A enable Finding B? (e.g. open redirect → OAuth code
  theft)
- Does Finding A reach the precondition of Finding B? (e.g. user-
  enumeration → targeted credential stuffing → ATO)
- Do A and B compose into something neither does alone? (e.g. SSRF
  reaches internal API + that API has weak auth → admin takeover)

Document the chain in `findings/CHAIN-NNN-slug.md` (using the same
template, but referencing the constituent findings). The chain often
deserves a higher severity than any constituent.

Examples of chains that look small individually but are critical
together:

- Subdomain takeover + cookie scoped to parent domain → session
  hijack via attacker-hosted JS.
- Self-XSS in profile + admin viewing user list → admin XSS → admin
  takeover.
- SSRF restricted to whitelisted hosts + open redirect on whitelisted
  host → arbitrary SSRF.
- Weak password reset + concurrent-login allowed without
  notification → silent ATO with delayed user awareness.
- Verbose error messages on registration + account-enum on login +
  no rate limit → credential stuffing with high hit rate.
- IDOR on a "preview" endpoint + sensitive data in response → mass
  enumeration of all users.

Chains are senior-tester findings. Make a deliberate pass at chains
*after* you have the individual findings list.

---

## 5. Defensive view — the kill chain as gap finder

Where a defender wants to break the chain, you should look for the
absence of break-points:

| Chain phase | Defensive break expected | Look for absence |
|-------------|--------------------------|------------------|
| Recon | Nothing to break — recon is unstoppable | n/a |
| Initial access | Strong auth, MFA, rate limit, lockout, breach-check | Any single one missing |
| Execution | Input validation, sandbox, WAF | RCE-class flaws |
| Persistence | File integrity monitoring, audit log | Webshells survive, no alerts |
| Privilege escalation | Least privilege, role isolation | Privilege checks per action |
| Lateral movement | Network segmentation, mTLS | SSRF reaches internal |
| Exfiltration | DLP, egress filtering | Outbound to anywhere allowed |
| Impact | Backups, audit, undo | No backups or no audit log |

Findings that "don't seem severe by themselves" become important
when they remove a defender's chain-break. For example: missing
audit log on admin actions is a Low individually; but if combined
with admin-takeover potential, it's how the takeover stays
undetected for months.

---

## 6. ATT&CK technique mapping in findings

In each finding, include an ATT&CK mapping when relevant:

```
- ATT&CK: TA0001 Initial Access / T1190 Exploit Public-Facing Application
- ATT&CK: TA0006 Credential Access / T1110.004 Credential Stuffing
- ATT&CK: TA0008 Lateral Movement / T1210 Exploitation of Remote Services
```

This makes findings translatable to defensive teams that monitor for
these techniques. They can ask "do we have a detection for T1190 on
this app?" and the answer points to a concrete control.

---

## 7. The aggregate kill-chain narrative

In the executive report, include a one-page section:

> **An attacker reaching the worst-case objective could do the
> following:** they would start with X (using finding 003), pivot
> via Y (chaining finding 014 and 022), and reach the objective via
> Z (finding 031). The current product has approximately N
> independent paths to this objective.

Operators understand "N paths to drained user balances" better than
they understand "23 findings in the technical report." The kill-chain
narrative is how you bridge those views.
