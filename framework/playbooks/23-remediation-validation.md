# Playbook 23 — Remediation validation

**Goal:** for each reported finding, verify the operator's fix
works, didn't introduce regression, and isn't trivially bypassable
with a variant payload.

**Stage in lifecycle:** 9.

---

## 23.1 The retest mindset

Operator-deployed fixes look correct in code review and unit tests
and *still* fail validation surprisingly often, because:

- Fix addresses the exact PoC payload but not encoding/case
  variants.
- Fix is on the surface that was reported but not on a sibling that
  has the same bug.
- Fix breaks legitimate flows that weren't covered by tests.
- Fix moves the bug to a different layer.

Your job is to confirm the fix is real, not theatrical.

---

## 23.2 Per-finding retest procedure

For each finding in `findings/NNN-*.md` with status `Fix in
progress` or `Reported`:

### Step 1: Read the original PoC

Re-read the finding doc. Confirm you can still reproduce the bug
in your test environment as it was reported.

### Step 2: Re-run original PoC

If the fix works, the original PoC fails. Capture the response.

If the original PoC succeeds, the fix didn't deploy or didn't work.
Document and notify the operator immediately.

### Step 3: Run variants

For each finding class, the fix may pattern-match the original
payload. Try variants to ensure the underlying fix is structural,
not pattern-specific.

#### XSS variants

- Encoding: `%3Cscript%3E`, HTML entities, double encoding.
- Case: `<Script>`, `<SCRIPT>`.
- Whitespace: `<script\t>`, `<script\n>`.
- Attribute injection: `" onload="alert(1)"`.
- DOM-based variants: same payload via fragment, postMessage.
- Different sink: same input lands in HTML attribute / JS context /
  CSS / URL.

#### SQLi variants

- Different payload: `OR 1=1`, `OR '1'='1`, time-based, boolean-
  based, UNION-based, error-based.
- Encoding: URL, hex, char(N), unicode.
- Case: `union`, `UNION`, `UnIoN`.
- Comments: `--`, `#`, `/* */`.
- Different parameter: same controller, different field.

#### IDOR / authz variants

- Method swap: GET → POST → PUT → DELETE.
- Parameter style: query → body → header → JSON nested.
- Sibling endpoint: same resource via different URL.
- Bulk endpoint: same operation in batch.

#### Race condition variants

- Higher concurrency.
- Different timing windows.
- Through a different code path.

#### Auth variants

- Same flow with different field name (`user` vs `username` vs
  `email`).
- Case-different username.
- Unicode-equivalent username.
- Different HTTP method.

### Step 4: Sibling check

If the fix is at the controller level, check whether siblings of
that controller (sharing parent class, similar patterns) have the
same bug. Often a fix is applied to one route while three others
with the same flaw remain.

### Step 5: Regression check

For non-trivial fixes, verify legitimate flows still work:

- Login as a normal user works.
- Place an order works.
- Reset password works.
- Etc.

You're not the QA team, but you should at least exercise the
adjacent legitimate flows enough to spot obvious breakage.

### Step 6: Update finding

Append to the finding's `## Re-test` table:

```
| Date       | Tester | Result | Notes |
|------------|--------|--------|-------|
| 2026-05-04 | OBSIDIAN | Verified Fixed | Original PoC fails 401; variants A, B, C also fail |
```

Set the finding's `Status` to one of:

- **Verified Fixed** — original PoC fails, all variants fail, no
  regression.
- **Partially Fixed** — original PoC fails but a variant succeeds.
  Keep finding open with a sub-note.
- **Bypassed** — fix is bypassable trivially. Keep finding open.
- **Risk Accepted** — operator declined to fix; document reason.
- **Will Not Fix** — operator declined and won't reconsider;
  document reason and compensating controls if any.

If Partially Fixed or Bypassed, it's reasonable to open a sub-
finding for the bypass variant.

---

## 23.3 Net-new findings during retest

Sometimes the fix introduces a new bug. Common ones:

- New endpoint added for the fix that has its own auth gap.
- Fix uses a new dependency with its own CVE.
- Fix's logging is overly verbose, leaking secrets.
- Fix's error message is informative enough to enable enumeration.

When found, file as a new finding (`findings/NNN+1-*.md`) and add
it to the retest report.

---

## 23.4 Deliverable: retest report

`reports/retest.md` summarizes the retest outcomes:

| Finding | Original Severity | Status | Notes |
|---------|-------------------|--------|-------|
| 001 | Critical | Verified Fixed | 2026-05-04 |
| 002 | High | Bypassed | Variant succeeds; opened 023 |
| 003 | High | Risk Accepted | Operator decision |
| ... | ... | ... | ... |

Plus per-finding retest sections (the table from each finding doc,
consolidated).

---

## 23.5 Phase exit checklist

- [ ] Every finding has a retest entry.
- [ ] Original PoC re-run on each.
- [ ] Variants tried.
- [ ] Sibling endpoints checked.
- [ ] Regression spot-checked.
- [ ] New findings (if any) opened.
- [ ] `reports/retest.md` written.
- [ ] Operator briefed on remaining open items.
