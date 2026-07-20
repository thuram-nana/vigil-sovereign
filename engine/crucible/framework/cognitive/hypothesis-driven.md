# Hypothesis-driven testing

Senior testers don't poke at apps and hope. They form **explicit
hypotheses**, design **falsifiable tests**, and update beliefs based
on evidence. This is the same loop scientists use; it works for the
same reason.

---

## 1. The hypothesis form

A useful hypothesis has four parts:

> **Given** [context], **if** I [action], **then** I will observe
> [result], **because** [model of how the app works].

Examples:

- *Given a logged-in session, if I POST /api/profile with `role=admin`
  in the body, then the user record will have role=admin afterward,
  because the controller probably uses mass-assignment from the
  request body.*

- *Given the password reset endpoint accepts an email parameter, if I
  send a request with `Host: attacker.example.com`, then the reset
  email will contain a link to attacker.example.com because the app
  probably builds the URL from the request's host header.*

- *Given the order placement endpoint accepts a `quantity` field, if
  I send a negative quantity, then the user balance will be credited
  (not debited) because the price calculation is probably
  `quantity * rate` without bounds checks.*

The "because" is the key. It states your model. When the test refutes
the hypothesis, the "because" tells you what part of your model is
wrong, which guides the next hypothesis.

---

## 2. Generating hypotheses — forcing breadth

The most common failure: form one hypothesis, fall in love with it,
test only it, miss everything. Defeat that with a forcing function:
**generate at least five hypotheses before testing any.**

Five-hypothesis prompts:

- "If this app has a flaw of class X, what would I observe at this
  surface?" — for X in {SQLi, IDOR, SSRF, race, business-logic, SSTI,
  deserialization, auth-bypass, mass-assignment, XXE, prototype-
  pollution, command injection, cache poisoning, request smuggling,
  open redirect}.
- "What would a {script kiddie / criminal / nation-state / insider}
  try here that I haven't?"
- "What invariant is the developer enforcing? What if I violate it?"
- "What's the side effect I'm not observing?"
- "What if I do this twice simultaneously?"
- "What if I do this with no auth? With another user's auth? With
  admin auth? With a malformed token?"
- "What if the input is empty / null / very long / unicode / negative
  / a different type / an array when a scalar is expected?"

If five doesn't come, your model is too thin. Go back to recon /
mapping / reading the source until you can.

---

## 3. Cheap-test design

For each hypothesis, ask: **what is the cheapest test that could
refute it?**

"Cheap" means: smallest payload, simplest tool, least state change,
easiest to clean up. The cheapest test is usually a single curl with
one field changed.

Cheap tests have huge advantages:

- You can run many of them, so you cover more hypotheses.
- They're easy to repeat / share with the operator.
- They make the result unambiguous; complex tests have many failure
  modes.

Pyramid of expense:
1. Single curl with one parameter change.
2. Browser exercise with DevTools open.
3. Burp repeater session with manual edits.
4. Burp Intruder with a small wordlist.
5. Custom Python with httpx (race conditions, async).
6. nuclei with curated templates.
7. sqlmap / ffuf at scale.
8. Coordinated multi-step exploit chain.

Start at level 1. Move up only when level N can't refute the
hypothesis.

---

## 4. Falsifiability — what evidence would change my mind

Every hypothesis must have a **stop rule**: an observation that
disproves it.

Examples:
- "If the response is identical in body and timing across both
  payloads, this hypothesis is refuted."
- "If two concurrent requests both return 200 with order IDs but
  the balance is correctly debited twice, the race-condition
  hypothesis is refuted."
- "If the server returns 401 even with the forged JWT, the auth-bypass
  hypothesis is refuted for this signing key."

If you can't name what would refute, you don't have a hypothesis —
you have a hope. Hopes don't generate falsifiable tests; they generate
endless poking.

---

## 5. Confirmation discipline

When a test seems to confirm a hypothesis, pause before declaring
victory. Three checks:

- **Reproducibility**: run the same test twice. If results differ,
  the bug is timing-dependent or you misread the first result.
- **Specificity**: change one element of the payload at a time. Is
  the fault really where you think it is, or is it somewhere else
  that happens to fire under your conditions?
- **Impact**: walk the side-effects. The response was 200, but did
  the database actually change? The balance updated, but did an
  audit log record fire? An apparent bug that doesn't have side-
  effects may be a UI gloss, not a real bug.

A finding is confirmed when reproducibility, specificity, and impact
are all locked in.

---

## 6. Refutation is value

Half the time, the hypothesis you formed is wrong. **That's the
point.** Refutations are not failures — they're how you reduce the
search space and increase confidence in what's left.

Document refutations in `notes/hypotheses.md` with:

```
- [date | phase] HYPOTHESIS
  Reason: ...
  Test: ...
  Result: refuted — <what was actually observed>
  Implication: <what your updated model is>
```

If you don't write down refutations, you'll re-test the same idea
later. Worse, you'll lose the implication — the small update to your
model that the refutation gave you.

---

## 7. Surprise — the highest-value signal

When a test produces a result that fits *none* of your hypotheses,
**stop and investigate**. Surprise is the marker of a model error,
and model errors are exactly where bugs hide.

When surprised:
1. Do not move on.
2. Capture the response in full.
3. Re-orient: what's actually happening? What does the app's response
   tell me about its internals?
4. Generate fresh hypotheses against the new observation.
5. Test the most consequential one.

Senior testers' best findings come from chasing surprises. Junior
testers move past them because they don't fit the test plan.

---

## 8. Anti-patterns

- **Confirmation bias**: testing only payloads that would confirm.
  Always include the variant that should *not* trigger the bug if
  the hypothesis is right; it's your control.
- **Hypothesis creep**: when the test refutes, mutating the
  hypothesis post-hoc to fit the new data. That's not science; it's
  rationalizing. Mark refuted, form new hypothesis cleanly.
- **Single-shot conviction**: declaring a finding from one
  observation. Reproduce, isolate, confirm impact.
- **Ignoring the boring response**: the 404 that "should have been"
  a 403, the 200 that "should have been" a 401, the empty body that
  "should have been" a redirect — these are the surprises.
- **Skipping the "because"**: if your hypothesis has no model behind
  it, you can't update on the result. You're just rolling dice.

---

## 9. Hypothesis log format

Use this format in `notes/hypotheses.md`. Append; don't edit history:

```
## H-NNN — short title
- Phase:        <phase>
- Surface:      <endpoint / feature / flow>
- Class:        <SQLi / IDOR / race / etc.>
- Hypothesis:   Given ..., if I ..., then ..., because ...
- Refute on:    <observation that would disprove>
- Test:         <command or steps>
- Result:       confirmed → finding NNN | refuted | surprised
- Implication:  <what this means for the model>
- Date:         YYYY-MM-DD
```

Example:

```
## H-007 — Mass-assignment of role on profile update
- Phase:        4 (vuln-hunt — auth/authz)
- Surface:      PUT /api/profile (logged in as low-priv user)
- Class:        mass-assignment / privilege escalation
- Hypothesis:   Given a logged-in session, if I PUT /api/profile with
                {role: "admin"} in JSON body, then the next request
                will be admin-authenticated, because the controller
                likely binds request fields to the user model without
                a fillable allowlist.
- Refute on:    role unchanged after the PUT (verify via subsequent
                GET /api/profile and via attempt to access admin
                endpoint).
- Test:         curl -X PUT https://target/api/profile -H 'Cookie:…' \
                  -H 'Content-Type: application/json' \
                  -d '{"name":"test","role":"admin","is_admin":true}'
- Result:       refuted — server returned 200 but subsequent GET shows
                role=user; admin endpoint still 403.
- Implication:  Controller has at least basic allowlisting on profile.
                Try other update endpoints (settings, preferences,
                notification config) — those are usually less hardened.
- Date:         2026-05-04
```
