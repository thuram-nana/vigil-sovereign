# How to start

This document gives you the literal text to paste into Claude Code as
your first message in different scenarios.

---

## Scenario A: brand new engagement, brand new target

Copy a target template, then start Claude Code in this directory and
send the message below.

```bash
cp -r targets/_template targets/<your-target-shortname>
cd /path/to/crucible
claude
```

**First message:**

```
You are OBSIDIAN per the constitution in CLAUDE.md.

I am the operator. I am the legal owner of <target system>, available
at <primary URL>, and I authorize you to conduct an authorized owner-
test against it under the framework rules.

I have created the target directory at targets/<your-target-shortname>/.
The charter is unfilled.

Please:
1. Read CLAUDE.md, ENGAGEMENT-LIFECYCLE.md, and the cognitive framework.
2. Walk me through filling targets/<your-target-shortname>/charter.md
   end to end. Ask one section at a time and propose drafts I can
   confirm or edit.
3. After the charter is finalized, propose a Stage 1 threat-modeling
   plan tailored to what we discussed.

Don't touch the target until the charter is signed.

Context to carry forward:
- <Target type / what it does, in one sentence>
- <Stack hints if known: PHP/Laravel/Node/Django/etc>
- <Posture preference: TEST / AUDIT / EMULATE — see opsec-discipline>
- <Known concerns or past incidents to focus on>
- <Whether you'll deliver source code, and when>
```

---

## Scenario B: resuming an in-progress target

```bash
cd /path/to/crucible
claude
```

**First message:**

```
You are OBSIDIAN. The active target is <target-shortname>.

Pick up where the last session left off:
1. Read CLAUDE.md to refresh.
2. Read targets/<target-shortname>/charter.md to confirm authorization
   is current.
3. Read targets/<target-shortname>/notes/engagement-log.md to
   reconstruct context — pay attention to the most recent entries.
4. Read recent findings in targets/<target-shortname>/findings/.
5. Summarize back to me: current stage, last significant action,
   top 3 open threads, what you propose to do next.

Wait for my confirmation before sending traffic to the target.
```

---

## Scenario C: switching active target mid-conversation

If you have multiple targets and want OBSIDIAN to switch:

```
Switch active target to <other-target-shortname>.

Read targets/<other-target-shortname>/charter.md, threat-model.md, and
notes/engagement-log.md. Summarize current state and propose next move.

Treat anything in targets/<previous-target-shortname>/ as read-only
context now; we are operating against <other-target-shortname>.
```

---

## Scenario D: handing OBSIDIAN source code (Stage 7)

```
The source code for <target-shortname> is now at
targets/<target-shortname>/loot/source/.

Begin Stage 7 (source code review) per playbook 20.

First, do a quick orientation pass:
1. Identify framework, language, LOC, structure.
2. Cross-reference routes against your endpoint inventory in
   recon/enum/inventory.md — note any endpoints we missed.
3. Read controllers for each currently-open hypothesis in
   notes/hypotheses.md and tell me which are confirmed by source,
   which are refuted, and which need more code reading.

Then propose the deep-dive priority order across the codebase.
```

---

## Scenario E: post-fix retest

```
The operator has deployed fixes for the findings in
targets/<target-shortname>/findings/.

Begin Stage 9 (remediation validation) per playbook 23.

For each finding in numeric order:
1. Re-run the original PoC.
2. Run encoding / case / whitespace / chained-field variants to ensure
   the fix isn't trivially bypassed.
3. Update the finding's Status field and append a Re-test entry.
4. If a fix introduces regression in legitimate flows, flag it.

When complete, write reports/retest.md.
```

---

## Operator quick commands during an engagement

After OBSIDIAN is running, you can use any of these freely:

- *"status report"* — checkpoint summary at any time.
- *"go to stage N"* — advance phases.
- *"pause / stop"* — halt all activity.
- *"explain finding NNN in plain language"* — non-technical summary.
- *"critique your work in the last hour"* — force a self-critique
  cycle.
- *"what threads are open?"* — lists current hypotheses.
- *"what haven't you tested yet?"* — runs the coverage check.
- *"if you had one more day on this, what would you do?"* — the
  prompt that catches the "almost-done-but-actually-not" state.
- *"surface anything critical you have not yet told me"* — emergency
  pull, in case OBSIDIAN was holding for phase summary.

---

## Operator pre-engagement checklist (one-time)

Before you let OBSIDIAN start any engagement:

- [ ] You own or have written authorization for the target.
- [ ] You can run Claude Code (`claude.ai/code`).
- [ ] You have a stable IP that the target's logs can correlate.
- [ ] You have created at least 2 test user accounts on the target
      (for IDOR / role tests). Tag them per the charter prefix.
- [ ] If applicable, you have a staging environment for destructive
      tests.
- [ ] Your hosting provider's ToS permits security testing of your
      own app from your IP. (Most do; a few shared hosts require
      written notice.)
- [ ] You've decided whether you'll deliver source code, and when.
