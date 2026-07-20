# Self-critique routine

A structured "what am I missing?" protocol you run at every phase
boundary, every 30-minute thread, and before declaring a target done.
This is the antidote to confirmation bias and depth fixation. It is
not optional.

Do this in writing (in `notes/engagement-log.md`), not in your head.
Writing forces honesty.

---

## 1. Quick critique (5 minutes, run often)

Five questions. Answer each in one or two sentences:

1. **What am I doing right now? Is it the highest-EV action available
   to me?**
   If "no" or "I'm not sure", what's higher-EV?

2. **What's my current hypothesis? What evidence would refute it?**
   If you can't name a falsifying observation, you don't have a
   hypothesis — you have a hope. Stop, form a real hypothesis.

3. **What's been surprising in the last hour, and have I followed
   up on it?**
   Surprise is the marker of a model error. Model errors are where
   bugs live. If you noticed something weird and moved on, go back.

4. **What classes of attack have I not even considered against this
   surface?**
   Walk the bug-class catalog briefly. If a class fits the surface
   and you haven't generated a hypothesis for it, do so now.

5. **Where am I likely deceiving myself?**
   Specific. "I want this to be vulnerable so I'm reading the
   response generously." "I'm tired and skipping reproduction." "I
   chose the easy thread, not the high-EV one."

If any answer reveals drift, fix it before continuing.

---

## 2. Phase critique (15–30 minutes, at every phase boundary)

Run this when you complete a phase or are about to declare one done.

### 2.1 Coverage check

For each surface in the target's inventory:
- Has every relevant playbook been run against it?
- Has every relevant attack class been hypothesized about it?
- Is there a finding, a refutation, or a documented "deferred to
  phase X" for each combination?

Mark the attack tree (`targets/<name>/attack-tree.md`) — every leaf
should be tested / found-vulnerable / blocked / deferred-with-reason.
Leaves marked "not started" without a reason are gaps.

### 2.2 Class check

Walk the master attack-class list and tick what you've explored:

- [ ] Information disclosure (passive recon, docs, error messages,
       source maps, JS bundles)
- [ ] Authentication weaknesses (login, registration, reset, 2FA,
       lockout)
- [ ] Session management (cookies, fixation, lifecycle, JWT)
- [ ] Authorization (vertical, horizontal, mass-assignment)
- [ ] CSRF
- [ ] Cross-site scripting (reflected, stored, DOM)
- [ ] Injection (SQL, NoSQL, LDAP, OS, SSTI, XXE, expression-
       language)
- [ ] SSRF
- [ ] File upload
- [ ] Open redirect / SSRF-adjacent URL handling
- [ ] HTTP request smuggling / desync
- [ ] Cache poisoning / cache deception
- [ ] Race conditions
- [ ] Business logic (per-domain abuse)
- [ ] Cryptography (TLS, JWT, custom crypto, weak hashing)
- [ ] Deserialization
- [ ] Prototype pollution
- [ ] Subdomain takeover
- [ ] CORS misconfiguration
- [ ] Clickjacking, postMessage abuse
- [ ] Information disclosure via headers / status / timing
- [ ] DoS (resource exhaustion patterns) — non-destructive only
- [ ] Cloud (IAM, metadata, misconfigured storage, exposed services)
- [ ] Container / Kubernetes (escape, RBAC, secrets)
- [ ] CI/CD / supply chain (workflow injection, dependency confusion)
- [ ] Identity / SSO (OAuth, SAML, OIDC flaws)
- [ ] Mobile (if mobile app exists)
- [ ] LLM / AI (if LLM features exist)

A class without a tick is a gap. Either explain why it doesn't apply
or open a thread for it.

### 2.3 Adversary check

For each realistic adversary in the threat model, ask: "Have I
emulated this adversary's likely path?"

- Script-kiddie: ran the loud scans, fuzzed the obvious surfaces?
- Criminal: covered the money paths and ATO vectors thoroughly?
- Insider: tried the "former employee with credentials" scenario?
- Supply-chain: audited deps, build pipeline, vendored libs?

---

## 3. Drift check (run any time you've spent over an hour)

Three questions:

- **Am I still working on the original objective, or have I drifted
  to something more interesting but lower-impact?**
- **Have I been documenting? When was the last entry in
  `command-log.md` and `engagement-log.md`?**
- **What did the last 60 minutes produce in terms of confirmed
  findings, refuted hypotheses, or new threads opened?**
  If the answer is "nothing", run the pivot protocol now.

---

## 4. Final critique — before declaring done

Before you write "engagement complete" in the engagement log, walk
this list. If any answer is "no" or "not really", you're not done.

1. Is every charter objective addressed in the report?
2. Has every surface in the inventory been tested?
3. Has every leaf in the attack tree been resolved?
4. Have you done a source-code pass (if source was available)?
5. Have you re-tested every reported finding after the operator's
   patches?
6. Have you written the executive, technical, and remediation-roadmap
   reports?
7. Have you cleaned up all test artifacts (`notes/test-artifacts.md`)?
8. Are there any open hypotheses you haven't closed?
9. Has the operator confirmed they have what they need?
10. Have you asked yourself "if I were going to find one more bug,
    where would I look?" and pursued the answer?

The last question is the single most useful one. Senior testers
always have one more thread to pull. The discipline is to know when
the marginal next thread isn't worth the time, but to have at least
*considered* it.

---

## 5. Anti-patterns the routine catches

- **"I tested authentication" without specifying which sub-tests.**
  The routine forces granular accounting.
- **"There's no XSS"** without naming the payload set tried and the
  contexts walked.
- **Spending three days on the same suspected bug without a working
  PoC.** The 30-minute drift check forces re-evaluation.
- **Skipping classes that "don't apply"** — the class check requires
  an explicit reason for skipping.
- **Confirmation bias dressed as thoroughness.** The "where am I
  deceiving myself?" question targets this directly.
- **Calling the engagement done because the playbook is done.** The
  finals critique enforces the "what would I check if I had one more
  hour?" question.

---

## 6. Output

After every critique, append to `notes/engagement-log.md`:

```
## YYYY-MM-DD HH:MM — critique (quick / phase / final)
- Drift detected: <yes/no — what>
- Coverage gaps:  <list>
- Threads opened: <list>
- Threads closed: <list>
- Decision:       <continue current / pivot to X / advance phase / declare done>
```

This log is your audit trail of self-discipline. The operator can
read it and see that you actually challenged your own work. So can
you, the next time you start a session and need to pick up from
where you left off.
