# Pivot protocols

When a thread runs cold, you do not give up on the target. You give
up on the **thread** and pick another. This document gives you
structured ways to generate the next thread when the current one is
stuck.

Trigger this protocol when:
- 30+ minutes on a single thread without progress.
- Hypothesis refuted, no immediate next hypothesis.
- WAF / rate limit / lockout actively blocking the current approach.
- You realize you've been pattern-matching for an hour without
  forming hypotheses.
- Phase boundary.

---

## 1. The two-minute reset

Most "stuck" feelings are a working-memory problem, not a real wall.
First thing to do: write down where you are.

```
Where I am: ___
What I was trying: ___
What blocked me: ___
What I learned (even if negative): ___
What's the next-most-promising thread I haven't tried?
```

Two minutes of writing usually surfaces the answer. If it doesn't,
proceed to systematic generation below.

---

## 2. Surface pivot — same class, different surface

If the bug class is real but the surface you tried is hardened, walk
adjacent surfaces:

- **XSS hardened on `/login`?** Try ticket subjects, profile names,
  child-panel branding, custom email templates, support reply, search
  reflection on error pages, header reflection.
- **SQLi parameterized on the API?** Look at admin reports, search
  with sort/order_by, legacy endpoints, CSV/Excel export, custom
  query builders.
- **IDOR blocked on numeric IDs?** Try UUID guessability, batched
  endpoints (`?ids=1,2,3`), GraphQL alias enumeration, sibling
  resources of the same parent (attachments, comments, history).
- **SSRF blocked on URL field for avatar?** Try child-panel logo URL,
  webhook test, RSS-feed import, "import order list from URL", PDF
  rendering, screenshot/preview of external page.
- **Auth bypass blocked on /admin?** Try API endpoints (often less
  hardened), method swap (`POST /admin/users`), header-trust tricks
  (`X-Original-URL`, `X-Forwarded-For`), path normalization
  (`/admin/./users`, `/admin//users`, `/admin%20`).

The bug-class catalog at `framework/knowledge-base/attack-techniques/`
lists every adjacent surface for each class. Read the relevant file.

---

## 3. Class pivot — same surface, different class

If you've explored a surface for SQLi without success, the surface
may still have other classes. Walk through:

- Auth bypass / authorization
- Injection (other forms: NoSQL, LDAP, OS command, SSTI, expression
  language)
- Race condition
- Business logic (negative values, type confusion, currency, decimal,
  state machine)
- Mass-assignment
- Server-side request forgery (if URL-shaped fields)
- Deserialization (if the input looks structured)
- Cache poisoning (if served via caching layer)
- Rate-limit / lockout DoS

Often a surface that looks "uninteresting" for the class you tried
yields a different class on the second pass.

---

## 4. Adversary pivot — what would X do here

When stuck, model a different adversary and let them choose the
attack:

- **Script kiddie**: would point Nuclei at it with all templates.
  What would the loudest scan find that you missed?
- **Financially-motivated criminal**: would target the money flow.
  Have you fully exhausted balance, refund, coupon, deposit,
  withdrawal, payment-webhook surfaces?
- **Insider with low privilege**: would abuse known internal
  knowledge. What would a former admin / former employee with
  read-only access try? (Exposed admin paths, disabled-but-not-
  removed accounts, legacy auth tokens.)
- **Supply-chain attacker**: would target dependencies. Have you
  audited the dependency tree, looked at vendored libraries, checked
  for typo-squat / dependency-confusion candidates?
- **Nation-state**: would prefer chained low-severity for stealth
  rather than one high-severity that triggers alerts. Have you
  thought about chaining your medium findings into a high-impact
  attack?
- **Bot / automated**: would find the most common low-hanging fruit
  systematically. Have you run the standard fuzzes (`raft-medium-
  directories`, common backup files, exposure templates) on every
  in-scope host?

Each adversary lens generates a different test plan. Use the one
that's the realistic top threat for the operator's product, then use
two more to cover blind spots.

---

## 5. Layer pivot — go up or go down

If you've been hitting the application layer hard, change layer:

- **Go down**: TLS, HTTP layer (smuggling, request interpretation),
  load-balancer behavior, WAF behavior, DNS, network services.
- **Go up**: client-side (JS that does sensitive work, postMessage,
  CORS), CDN/cache (poisoning, web cache deception), session storage,
  service workers.
- **Go sideways**: build/deploy pipeline, secrets management, CI/CD,
  cloud IAM, container orchestration, configuration drift, supply
  chain.

The bugs the operator fears most are usually at a layer they didn't
consider. Layer pivot finds those.

---

## 6. Time pivot — historical and futures

- **History**: Wayback Machine, gau, archive.org, GitHub diff history.
  Old versions of the app sometimes had endpoints/parameters that
  still work but aren't linked. Old commits sometimes have hardcoded
  secrets that are still valid.
- **Recent change**: was something deployed recently? New code is
  buggier than old code. Diff the live app's HTML/JS against an
  archived copy to spot recent additions.

---

## 7. Source pivot — go white-box for one question

If the operator has shared source (or will), use it not as a separate
phase but as a tool when stuck. Often a 60-second look at the
controller answers a question that would take 60 minutes of black-box
guessing:

- "Is this parameter parsed as JSON or as form?"
- "Is there an auth check before or after the data load?"
- "Is the random source `mt_rand` or `random_bytes`?"
- "Is the SQL parameterized or concatenated?"

Surgical source dips during black-box are not "cheating" — they're
the senior tester's most efficient move. Document the dip in
`notes/source-questions.md`.

---

## 8. Tool pivot — different lens

If you've been driving everything from curl/manual, try:

- **Burp Suite** for visual diffing and Comparer.
- **mitmproxy** for scripting on the wire.
- **Caido** for query collection management.
- **Browser DevTools** for client-side state and DOM Invader for DOM
  XSS.
- **Wireshark** for the actual bytes when HTTP feels off.
- **`semgrep`** if you have source — can grep semantic patterns for
  "controller without auth check".

A different tool reveals different details.

---

## 9. Constraint pivot — relax a constraint

You may have over-constrained yourself. Common ones to relax (after
checking with the operator that it's OK):

- "I assumed I had to be unauthenticated" — try as low-priv user.
- "I assumed it had to be a single request" — try a multi-step
  exploit chain.
- "I assumed I was alone" — try collaborating with another role
  (admin clicks attacker's link → CSRF chain).
- "I assumed I needed a 200" — a 500 with a stack trace can be the
  bug.
- "I assumed the WAF was the gate" — sometimes the WAF only inspects
  headers; the body is unfiltered.

Each relaxation opens up a class of tests you weren't running.

---

## 10. Operator pivot — ask

When you've genuinely exhausted hypotheses, **ask the operator**:

- "Is there a feature I might be missing? An admin tool, batch job,
  worker, scheduled task, internal-only endpoint?"
- "Is there a known sensitive operation we haven't discussed?"
- "Are there past bug reports / customer complaints that might hint
  at where bugs live?"
- "Is there a third-party integration whose interaction with the app
  I should look at more carefully?"

The operator built the system. They know things you can't infer from
black-box. Asking is not weakness; it's information access.

---

## 11. The "give up" question — when is it actually time

You **only** declare a target safely-tested when:

1. Every charter objective has been pursued.
2. Every surface from the inventory has been touched by every
   relevant playbook.
3. The attack tree is fully marked (tested / found-vulnerable /
   blocked / deferred — no leaves marked "not started" without a
   reason).
4. A self-critique pass produces no new threads.
5. Source code review (if available) is complete.

If any of these is incomplete, you're not done — you're stuck. Go
back to step 1 of the pivot protocol.

The operator's measure of done is how many real adversaries succeed
against the deployed product. You optimize for that, not for "I
finished the playbook."
