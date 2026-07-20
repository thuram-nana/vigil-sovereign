# OPSEC discipline

OPSEC (operational security) for the offensive operator means: don't
break the target, don't pollute its data, don't get yourself confused
with a real attacker, and (in red-team mode) don't trip the defenders
unnecessarily.

The right OPSEC posture depends on the engagement type. The charter
(`targets/<name>/charter.md`) sets the posture explicitly. This
document explains the postures and the practices behind them.

---

## 1. Three postures

| Posture | When | Behavior |
|---------|------|----------|
| **TEST** (default for owner-test) | Operator wants completeness, will correlate scan logs themselves | Loud-but-tagged. Identifiable user-agent, stable IP, high coverage, throttled |
| **AUDIT** (compliance-style) | Engagement output is a control-test artifact | Quiet, scheduled, well-documented, narrow-scope per item |
| **EMULATE** (true red team) | Operator wants adversary emulation, often with a blue team unaware | Realistic adversary signature mimicry, OPSEC-disciplined, narrow noise |

Most engagements run in TEST. EMULATE is for when there's a blue team
or detection content to evaluate. AUDIT is for compliance contexts
(SOC 2, ISO 27001, PCI) where the format of the test matters as much
as its findings.

The agent operates in TEST by default. It does not silently shift to
EMULATE without explicit charter authorization.

---

## 2. TEST posture — the defaults

These are the rules unless the charter says otherwise.

### 2.1 Identification

- **User-Agent** on automated tools: `OBSIDIAN/1.0 (authorized
  owner-test <YYYY-MM-DD>)`. The operator can grep their logs.
- **Source IP**: stable. No Tor, no rotating proxies, no random
  residential IP services. The operator wants to correlate.
- **Test artifacts** tagged with a recognizable prefix
  (`OBSIDIAN-TEST-`, or whatever the charter specifies). Used in
  usernames, order notes, support ticket subjects, file names —
  anywhere the platform allows free text.

### 2.2 Pace

- Default scan concurrency: 5–10 threads.
- Default rate limit: respect 429 responses; back off exponentially.
- Heavy scans (full nuclei, full ffuf, sqlmap with high risk):
  off-peak hours per the charter.
- Long-running tools (ffuf, full nuclei): operator notified before
  start.

### 2.3 No surprise destruction

Anything that could change state at scale requires explicit pre-
approval. Examples:

- Mass user creation (>10 accounts).
- Mass-order placement.
- Touching admin settings on production.
- Triggering payment-provider callbacks on production with real
  money.
- Database modifications via SQLi (read-only PoC only without
  approval; UPDATE/DELETE proof requires explicit go-ahead).
- File uploads beyond a small set, especially executable types.
- Webhook flooding.

### 2.4 No real-user contact

Never trigger:
- Password resets to real user emails.
- 2FA codes to real user phones.
- Notifications/SMS to real users.
- Real-money charges/refunds to real customers.

If a test would do any of these, redesign or stage.

### 2.5 No third-party attack

Even in scope, do not attack third parties (covered in CLAUDE.md § II
and the charter). Throttle interaction with their endpoints.

### 2.6 Cleanup discipline

Every artifact created → row in `notes/test-artifacts.md`. Before
engagement close (stage 9), every row gets a cleanup status. Things
to track:
- Test accounts created.
- Orders placed.
- Tickets opened.
- Files uploaded.
- DB rows known to have been written outside above (e.g. via SQLi
  inserts).
- Sessions still active.
- API keys issued.

---

## 3. AUDIT posture additions

When in compliance mode:

- Each test action is logged with a control reference (e.g.
  WSTG-ATHN-04, ASVS V2.1.1).
- Findings are categorized to control families (PCI 8.x, ISO Annex A,
  NIST SP 800-53).
- "Test, document, attest" cadence: every control test produces an
  artifact suitable for an auditor's evidence file.
- Slower; favors completeness over speed.

The technical report has a control-mapping appendix.

---

## 4. EMULATE posture additions

When emulating a real adversary against a blue team:

### 4.1 Signature management

- User-Agent matches a plausible real adversary set (e.g. a known
  scanner the team actually sees, or a generic browser UA for
  manual-style traffic). **Per actor**, not random rotation. Real
  adversaries don't randomize per request.
- Source IP rotation **only** with explicit charter approval and
  documented set. Logs of which actor used which IP at which time
  must be kept (so the blue team can reconstruct after the
  engagement).
- Tools that fingerprint identifiably (e.g. `nuclei` default UA,
  `nmap` default scripts) are configured to match the chosen
  adversary profile or replaced with custom equivalents.

### 4.2 Pace

- Spread interactions over time to mimic real adversary cadence.
- Vary user-agent and timing per actor (one slow careful actor, one
  fast noisy actor, etc.) if the charter calls for it.

### 4.3 No "pentest tells"

A real adversary doesn't:
- Tag their accounts `OBSIDIAN-TEST-`.
- Use the same wordlist as everyone.
- Hit 50 login attempts per minute from one IP.
- POST `<script>alert(1)</script>` and look at the response.

Adjust accordingly. **However**, even in EMULATE, the engagement is
authorized — never cause real harm, never exfil real user PII, never
break production. The charter's hard limits are absolute even in
EMULATE.

### 4.4 Coordinated whitelisting (optional)

Some EMULATE engagements use "purple team" mode where the blue team
knows abstractly that an engagement is happening but not exactly
when. In that case, signature management is for *realism*, not for
evading detection — the goal is realistic detection content
evaluation.

---

## 5. Logging on your side

Even in EMULATE, you log everything you do, locally, in the working
directory. Two reasons:

1. The operator must be able to reconstruct after the engagement
   ("what was that scan from 03:14 UTC?").
2. You may need to attribute or de-attribute actions later if the
   blue team reports something they think you did and you didn't
   (or didn't and you did).

`notes/command-log.md` is the source of truth. Append, never edit.

---

## 6. Evidence handling

Sensitive data in evidence (real user credentials, real PII, real
keys) must be redacted before evidence leaves
`targets/<name>/evidence/` (which is gitignored). Redacted copies go
to reports. The originals stay in the working directory until
operator confirms cleanup.

Never paste raw sensitive data into chat with the operator if you
can avoid it. Reference by file path. The operator can read the file
locally.

---

## 7. What you do not do, ever, in any posture

These are absolute, regardless of charter language:

- Attack systems not in scope.
- Exfiltrate real user PII to anywhere outside the working directory.
- Damage data without explicit go-ahead and a recovery plan.
- Install backdoors / persistent agents / test malware on production.
- Use real customer credentials you have stumbled across (rotate &
  notify, don't use).
- Disclose findings to anyone but the operator before they're
  disclosed publicly by the operator.
- Misrepresent results — never claim a finding without a working PoC,
  never mark a finding fixed without a re-test.

The charter cannot grant exceptions to this list. If the operator
asks for one of these, decline and explain.

---

## 8. The "would I want this in court" test

For any meaningful action, ask: if this engagement ended up in
adversarial review (operator vs. customer, operator vs. partner,
operator vs. regulator), would I want this action and its
documentation to be the public record?

That includes: the command, the response, the impact, the cleanup,
the timing, the chain of authorization. If any of those would be
embarrassing, redesign before acting.

This is a slow test, but it sharpens the posture. The agent operates
on the operator's reputation as well as their security.
