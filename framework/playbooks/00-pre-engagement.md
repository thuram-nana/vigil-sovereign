# Playbook 00 — Pre-engagement

**Goal:** establish written authorization, define scope, set posture,
and align expectations before any traffic touches the target.

**Stage in lifecycle:** 0.

**Inputs:** the operator's stated target system and intent.
**Outputs:** signed charter at `targets/<name>/charter.md`,
populated working directory, agreed posture and communication plan.

---

## 0.1 Confirm OBSIDIAN's identity and rules

Before reading anything target-specific, the agent re-reads:

- `CLAUDE.md` (constitution)
- `ENGAGEMENT-LIFECYCLE.md`
- `framework/cognitive/opsec-discipline.md`

This is not redundant; it's the boot sequence. The constitution can
be updated; the agent reads the current version each session.

## 0.2 Initialize the target directory

If the target doesn't exist yet:

```bash
cp -r targets/_template targets/<shortname>
```

The shortname is lowercase, alphanumeric+hyphen, descriptive but
brief: `acme-portal`, `internal-crm`, `payments-api`.

## 0.3 Walk the charter section by section

Use `framework/templates/charter.md` as the structure. Don't ask the
operator to fill it alone — walk them through, propose drafts based
on what you already know about the target, ask for confirmation or
edit, write the result.

Sections to cover:

1. **Authorization attestation** — operator name, role,
   confirmation of legal authority, date.
2. **In-scope hosts and surfaces** — primary, subdomains, staging,
   API roots, admin paths.
3. **Out of scope** — third parties, sister sites, shared
   infrastructure, anything ambiguous.
4. **Test accounts** — what roles need to exist for testing
   (anonymous, low-priv user A, low-priv user B for horizontal IDOR,
   reseller / child tenant if applicable, admin if accessible on
   staging).
5. **Hard limits** — DoS, payment movement, real user contact, data
   exfil ceiling.
6. **Soft limits** — off-peak window, scan concurrency, rate-limit
   respect, no Tor / proxy rotation.
7. **Posture** — TEST (default), AUDIT, EMULATE. See
   `framework/cognitive/opsec-discipline.md` for what each means.
8. **Objectives** — what would a successful engagement look like to
   the operator? (Not "find all bugs" — more specific: "have
   confidence the panel survives a credential-stuffing attack",
   "verify our payment integration can't be forged", "confirm no
   prior compromise exists".)
9. **Stop conditions** — when must the agent stop and surface to
   operator immediately.
10. **Communication plan** — channel for emergencies, expected
    response time, who to escalate to if operator unavailable.
11. **Source-code delivery** — when and how source will be shared
    (Stage 7).
12. **Continuous testing intent** — is this one-shot, or the start
    of an ongoing program?
13. **Sign-off** — operator confirms.

## 0.4 Verify environment

```bash
bash framework/tools/verify.sh
```

If anything is missing, run `bash framework/tools/install.sh` and
re-verify.

Document the operator's source IP in
`targets/<name>/notes/opsec.md` so they can correlate with their own
logs. Confirm User-Agent and any other identifying header values.

## 0.5 Confirm test accounts

Walk through with the operator:

- Are the test accounts created? Tagged per the charter prefix?
- Do you (the operator) have credentials at hand?
- For the agent to use, store credentials only in
  `targets/<name>/loot/credentials.md` (gitignored). Never paste in
  chat unless absolutely needed for diagnostic, and never write to
  reports.

## 0.6 Initialize working notes

Each note file should have a clear initial state ready for
appending. The template directory provides them; verify they're
present:

- `notes/command-log.md`
- `notes/engagement-log.md`
- `notes/test-artifacts.md`
- `notes/hypotheses.md`
- `notes/source-questions.md`
- `notes/opsec.md`

If any are missing, copy from `framework/templates/notes/`.

## 0.7 Summary back to operator

At the end of pre-engagement, summarize:

- Charter version 1.0 signed (paste a one-paragraph summary).
- Posture chosen: TEST / AUDIT / EMULATE.
- Test accounts confirmed: <list>.
- Environment verified, tools installed.
- Next stage: 1 (threat modeling). Ask for go-ahead.

The operator confirms; the engagement proceeds.

## 0.8 Phase exit checklist

- [ ] Charter populated and operator-confirmed.
- [ ] Posture explicitly chosen and documented.
- [ ] Test accounts exist and credentials stored in `loot/`.
- [ ] Tooling verified.
- [ ] Working notes initialized.
- [ ] Operator approves moving to Stage 1.
