# `.claude/` — Agent Configuration

This directory configures the Claude Code agent that drives the CRUCIBLE
framework. The agent operates under the persona name **OBSIDIAN** and the
behavioural contract defined in `../CLAUDE.md`.

There is one configuration file here:

- **`settings.json`** — Claude Code permissions and environment.

JSON has no comment syntax, so this README carries the rationale that would
otherwise live as inline comments. Read it once before editing the settings.

---

## Permission philosophy

The settings.json is built around three rings of capability, each more
trusted than the next:

```
         ┌─────────────────────────────────────────────┐
         │  deny   — refused outright, no prompt       │
         │  ask    — prompts the operator first        │
         │  allow  — runs without prompting            │
         └─────────────────────────────────────────────┘
```

Membership is decided by **blast radius**, not by tool name:

- **allow** — read-only or scoped-write operations whose worst-case outcome
  is wasted CPU. HTTP requests to a target. File writes inside
  `targets/<engagement>/`. Reads of the framework. Search-engine queries.
  Tool invocations that respect their own rate limits.

- **ask** — operations that *could* be correct but could also be a mistake
  the operator wants to catch. Aggressive scans (`nmap -p-`, full-port
  masscan). Credential-dependent commands (sudo, ssh into someone else's
  box). Cloud CLIs that touch live infrastructure. Anything that writes
  outside the engagement folder. Container runtimes. C2 frameworks.
  Brute-forcers. Web fetches to domains not on the explicit allowlist.

- **deny** — operations that have no legitimate workflow inside this
  framework. Recursive deletes from the root, the home directory, or the
  framework itself. Fork bombs. `curl | bash` patterns that execute
  arbitrary remote code. Reverse shell handlers that listen on the
  operator's own machine (a real engagement uses isolated infrastructure,
  not the laptop running Claude Code). Reads of the operator's SSH keys
  or `/etc/shadow`. Writes that would mutate the framework itself.

The deny list also blocks edits to the framework's own canon —
`framework/cognitive/`, `framework/playbooks/`, `framework/checklists/`,
`framework/knowledge-base/`, `framework/templates/`, plus the top-level
`CLAUDE.md` and `README.md`. Engagement work happens in `targets/`. The
framework is shared infrastructure and shouldn't drift mid-engagement.
If you genuinely need to revise the framework, do it in a dedicated
maintenance session with these rules relaxed, not while OBSIDIAN is
hot on a hypothesis.

---

## What the allowlist is *not*

The allowlist is broad on intent: the agent should be able to run a real
web pentest end-to-end without a prompt every thirty seconds. That is
what makes the tool useful instead of theatrical.

But broad-on-intent is not the same as unbounded. Three guard rails are
worth noting because they look permissive at a glance:

1. **`Bash(curl:*)` is allowed, but `Bash(curl * | bash)` is denied.**
   Fetching an HTTP response is a normal pentest action; piping
   unverified content to a shell is a malware delivery vector.

2. **`Bash(sqlmap:*)` is allowed, but `sqlmap --os-shell`, `--os-pwn`,
   and `--file-write` are escalated to ask.** Detection and extraction
   are normal; pivoting to RCE on a target machine should always be
   confirmed with the operator and matched to the engagement charter.

3. **`Bash(git add:*)` and `Bash(git commit:*)` are allowed, but
   `git push` is escalated to ask.** Local commits are recoverable;
   pushing engagement data to a remote is a leak that cannot be undone.
   The `.gitignore` is the first line of defence here; this is the
   second.

---

## Environment variables

The `env` block sets four things:

| Variable | Purpose |
|----------|---------|
| `CRUCIBLE_ROOT` | Anchor path for relative tool resolution. |
| `CRUCIBLE_OPSEC_POSTURE` | One of `TEST`, `AUDIT`, `EMULATE`. Read by playbooks and scripts to scale aggression. Default `TEST`. |
| `CRUCIBLE_AGENT` | Persona name surfaced in test artefacts (e.g. `OBSIDIAN-TEST-foo@example.com`). |
| `CRUCIBLE_TEST_PREFIX` | Prefix applied to every account, file, comment, or token created during testing so the operator and the target can grep them out post-engagement. |

Switch posture by exporting the variable in the shell *before* invoking
Claude Code, or by editing this file and reloading the session. The
posture is not just decoration — it changes which playbook branches are
taken (see `framework/cognitive/opsec-discipline.md`).

---

## When to edit this file

Edit `settings.json` when:

- A tool you need is in `ask` and prompting on every invocation has
  become friction rather than a safety net. Promote it to `allow` —
  but only after thinking about what its worst-case behaviour is.

- A tool you don't trust is in `allow` and you want a confirmation
  step. Demote it to `ask`.

- The engagement scope changes. New target domains belong in the
  `WebFetch(domain:...)` allowlist; old ones can be removed.

Do not edit this file when:

- A single command is failing. Use the in-session permission prompt
  instead. Settings drift across engagements is how mistakes accrete.

- You're tempted to add `Bash(*)` to allow because it's faster.
  It's not faster. It's how a misplaced `rm` ends an engagement.

---

## Verifying the file

Always validate after editing:

```bash
python3 -c "import json; json.load(open('.claude/settings.json'))" \
  && echo "OK"
```

JSON is unforgiving; a stray comma will silently disable the agent's
permission model and fall back to defaults. Validate before committing.
