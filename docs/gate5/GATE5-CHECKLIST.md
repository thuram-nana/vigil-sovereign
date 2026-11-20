# Gate 5 — hands-on end-to-end and at-scale acceptance checklist

> **Status: the apparatus is in place; Gate 5 has NOT been run to a sign-off.** This is the document the owner runs
> Gate 5 against and signs. It lists every acceptance criterion of HANDOFF §13.2 (the wallet journey), §13.1 (the
> at-scale targets) and §7 (the definition of 100%), and says **how each is checked**:
>
> * `AUTOMATED` — an offline, deterministic test backs it (named in the row; a guard test fails if a named test file
>   does not exist);
> * `OWNER` — a hands-on step only the owner can take: Stripe **test mode** (never a live key or a real card), a real
>   browser or device, a deployment, the at-scale harness, a production flip;
> * `PENDING` — the slice that makes it checkable has not merged into this branch yet.
>
> Nothing here spends real money or calls a production model, and nothing deploys a server. The three production
> flips stay the owner's, after this validation (HANDOFF §6).

## How to run the automated part

```
# the whole-customer-app walk (needs node on PATH; CI sets VIGIL_REQUIRE_NODE=1, so a missing node FAILS):
<sovereign venv>/python -m pytest apps/sigil/tests/test_gate5_customer_e2e.py -q -rs

# the same, writing the per-screen census as the evidence to attach to the sign-off:
VIGIL_GATE5_EVIDENCE=/path/to/gate5-census.json <sovereign venv>/python -m pytest \
    apps/sigil/tests/test_gate5_customer_e2e.py -q -rs
```

The walk boots the **real page** under a node DOM — every script `index.html` loads, in its order, `app.js` verbatim
— signs in against a fake same-origin server whose data makes every real control render, and drives navigation the
way a browser does (a hash change fires `hashchange`; top-bar tabs are clicked). Over the **real loopback hop** it
then sends every read the page made to the real edge. `-rs` prints each **pending stage** with its reason: a screen
not yet merged is its own skipped test that turns into a real check the moment its route or control lands, so this
list is complete in shape today and goes green as the screens merge. The harness changes no customer-app or edge
behaviour; it only observes.

---

## A. Every customer screen is live, its own, wired, and honest

Hands-on: sign in, click every tab, press the main control on each screen, and confirm each loads, every button does
something, and every refusal says why. The walk asserts the same for each merged screen: its own heading and reads
(never the "being wired" placeholder, a load error, or a silent fall-back to the Overview), its real controls on the
page, and no dead button.

| Screen | Route | Acceptance | Check |
|---|---|---|---|
| Sign in | `#/login` | the sign-in form; "Continue with Google" when that is on | `AUTOMATED` `test_the_sign_in_screens_render_their_forms_with_no_dead_button` · `OWNER` passkey sign-in on a real device (arrives with #1147) |
| Create account | `#/signup` | the sign-up form; a confirmed sign-up lands in the new workspace | `AUTOMATED` `test_the_sign_in_screens_render_their_forms_with_no_dead_button` · `OWNER` a real email round trip |
| Recover password | `#/recover` | the reset request and set-new-password forms | `AUTOMATED` `test_the_sign_in_screens_render_their_forms_with_no_dead_button` |
| Google code (installed app) | `#/google-code` | the code box shown on return from the browser | `AUTOMATED` `test_the_sign_in_screens_render_their_forms_with_no_dead_button` · `OWNER` a real device hand-off |
| Overview | `#/` | the account and workspace cards | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` |
| Billing | `#/billing` | credits, wallet, subscription; the credit top-up offer with its Buy button | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` a Stripe test-mode purchase |
| Payment return | `#/billing/return` | "Payment received" and Back to Billing | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` the real return from Stripe |
| Invoices | `#/invoices` | the invoice table (or its empty state) | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` |
| Assets | `#/assets` | Request ownership challenge, Re-check now, Re-issue challenge | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` publish a real DNS or HTTP proof |
| Assessments | `#/assessments` | Launch (Quick / Deep, no number), Pause on a running assessment, View findings | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` a real run |
| Team | `#/team` | Add member, Change role, Remove; the founder's row read-only | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` |
| Monitoring (AEGIS) | `#/monitoring` | Turn on Observe / Respond, Switch to Respond, Turn off | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` real traffic through the gateway |
| Fix first | `#/fix-first` | the 0-100 posture with its twelve-week trend, then the open findings worst first, each with its standards and, where signed, its plain-language impact and exact fix; Retest where retests are on | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `OWNER` a real FACT's signed fix shown, then retested to Fixed |
| Attack path | `#/attack-path` | the SVG narrative of how proven findings chain into impact, each node a confirmed step; View findings (Area 11, behind `VIGIL_CUSTOMER_ATTACK_PATH`) | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` |
| Guide | `#/guide` | the whole-app guide; Replay the welcome tour | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` |
| Plans | `#/plans` | the trial, pay as you go and every plan the owner sells compared (price, credits each period, period); the workspace's plan; Choose (the existing checkout), Upgrade / Downgrade at renewal, Cancel plan, Keep my current plan | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `test_customer_plans.py` (a scheduled change rides the real drain at renewal) · `test_customer_area6_ui.py` · `OWNER` a Stripe test-mode switch and its renewal invoice |
| Reports | `#/reports` | Download report (HTML), Download PDF (only where the owner provisioned a renderer), the standards mapping of proven findings, never a claim that a control is met | `AUTOMATED` `test_every_merged_screen_renders_its_own_live_screen_with_no_dead_button` · `test_customer_report_export.py` · `test_compliance_rollup.py` · `OWNER` a PDF from the provisioned renderer, read by a person |
| Top bar | every tab | each tab, clicked, lands on a real route showing that route's screen | `AUTOMATED` `test_every_top_bar_tab_clicked_lands_on_its_own_screen` |

The screens still to come — each a skipped stage (`-rs` shows why) that becomes a real check when it merges:

| Pending screen | Route | Status | TODO |
|---|---|---|---|
| Account security | `#/security` | `PENDING` merged on main as #1147, not in this branch's base: `test_stage_account_security_screen` walks it, and checks its read on the real edge, at the rebase | §15.11 C3: authenticator-app and passkey set-up, passkey sign-in, the step-up prompt |
| Code (Red-Pen) | `#/code` | `PENDING` `test_stage_code_redpen_screen` | §15.11 C6: Connect GitHub, repositories, merge-blocking threshold and monthly spending limit, System review, Fix this, Disconnect |
| Retest | an action on a finding | `PENDING` `test_stage_assessments_retest_action` | §15.11 C1: Retest on a finding, a re-checked run |
| W6 billing dashboard and auto top-up | on `#/billing` | `PENDING` `test_stage_billing_w6_dashboard_and_auto_topup` | §15.11 C5 / B9: rates, the statement with balance-after, credits on hold, low-balance notice, auto top-up |
| Overview aggregation | on `#/` | `PENDING` `test_stage_overview_aggregation` | §15.11 C7: credits, hosts, assessments and monitoring together |

When a screen lands with a page flag of its own, add that flag to the walk's `_WALK_FLAGS` (its stage fails loudly,
showing the Overview, until you do); a new route no stage claims fails `test_the_screen_map_matches_app_routes`.

## B. The routes resolve end to end and refusals are honest

| Criterion | Check |
|---|---|
| every read the page fires, sent to the real edge over the loopback hop without a session, answers 401 (present), never 404 (absent) | `AUTOMATED` `test_every_read_the_walk_makes_resolves_on_the_real_edge` |
| the page reads only paths the edge routes; viewing every screen sends no write; nothing goes through a raw fetch | `AUTOMATED` `test_viewing_every_screen_reads_only_edge_routes_and_writes_nothing` |
| with the screens' switches off their routes are absent (404), not a masked 401 | `AUTOMATED` `test_a_flag_off_screen_route_is_absent` |
| a billing role is refused a testing read (403) and still reads billing | `AUTOMATED` `test_a_billing_role_is_honestly_refused_a_testing_read` |
| the walk boots exactly the scripts the page loads, and makes no network call | `AUTOMATED` `test_the_walk_boots_every_script_the_page_loads` |
| every route is walked or claimed by a pending stage | `AUTOMATED` `test_the_screen_map_matches_app_routes` |
| the per-screen census, bound to the sha256 of every script walked, as evidence | `AUTOMATED` `test_the_census_accounts_for_every_screen_and_is_saved_as_evidence` |

## C. The §13.2 wallet journey: buy, launch, pause, resume, settle, reconcile

Hands-on, end to end, in **Stripe test mode**. The `AUTOMATED` entries are the offline suites that prove each link
on its own. The one automated run of the whole chain, the simulated wallet E2E of §11.12, is not built yet
(§15.11 B8), so the end-to-end tie-up is an `OWNER` step until it lands.

| Step | Acceptance | Check |
|---|---|---|
| Sign up | a new account and workspace; one trial per verified email | `AUTOMATED` `test_provision_signup.py`, `test_trial_signup.py` · one trial per verified domain: `OWNER`, no automated check yet (HANDOFF §11.14: verify `governor/trial_policy.py`, add the domain dedup if missing) |
| Buy credits | checkout sends only a catalog price id and opens Stripe's hosted page; never a live key or a real card | `AUTOMATED` `test_customer_checkout*.py` · `OWNER` the test-mode purchase |
| Webhook to the billing drain | a signed Stripe event is re-fetched and credits the wallet from the fetched objects only; a replay is inert; the drain reads Stripe envelopes | `AUTOMATED` `test_billing_stripe.py`, `test_billing_spool_reader.py` · `OWNER` a real test-mode delivery and a re-sent one |
| Prove domain ownership | a proof is recorded only on the trusted verdict for the current token; no proof, no target authority | `AUTOMATED` `test_asset_ownership.py`, `test_customer_target.py` · `OWNER` publish a real proof |
| Launch with no estimate | Quick / Deep, no number on the page; the reservation holds credits | `AUTOMATED` `test_customer_launch_ui.py` · `OWNER` a real launch |
| Live consumption on the dashboard | what a run has used so far, while it runs | `PENDING` W6 (§15.11 C5): today only a completed run's used figure is shown (`test_customer_launch_ui.py`) · `OWNER` |
| Exhaust credits, pause with work preserved | the model gateway's terminal credit stop becomes a clean credit pause at the engage seam (M1c-2b) | `AUTOMATED` `test_phase_ledger_credit_pause.py`, `test_engage_worker_metered.py` · `OWNER` the real run |
| Sandbox top-up, then Resume | the credit-paused run resumes on the same meter after a top-up | `PENDING` W3 (§15.11 B2) · `OWNER`; the customer's own Pause / Resume control: `AUTOMATED` `test_launch_pause_resume_actions.py` |
| An oracle-confirmed FACT | the run produces a real, oracle-confirmed finding | `OWNER` a real engagement (any real model spend needs the owner's explicit authorisation; otherwise the fake upstream) |
| Exact settle | to the milli-credit; only the signed settle decision moves the sub-credit remainder | `AUTOMATED` `test_exact_settle.py` |
| The statement reconciles with the ledger (I4) | balance-after on every line; remaining and available-to-start exact | `AUTOMATED` `test_exact_statement.py` · `OWNER` read the real statement against the ledger |
| Failure injection | kill the gateway mid-request and the settle mid-way; a duplicate webhook; a duplicate completion signal | `PENDING` the simulated wallet E2E (§11.12) · `OWNER` |
| Two workspaces at once | two orgs run the journey concurrently, each sees only its own | `AUTOMATED` isolation: `test_customer_e2e.py` · `PENDING` the concurrent money journey (§11.12) |
| `vigil doctor` / `vigil ready` | both clean after the run | `OWNER` (needs a deployment) |
| Repeat with the fold cache | the whole journey again with `VIGIL_FOLD_CACHE_ENABLED=1` | `OWNER` · the fold cache's own correctness: `AUTOMATED` `test_fold_cache_*.py` |

## D. Operations

| Criterion | Check |
|---|---|
| no real payment, no production model call and no server deploy during the validation | `AUTOMATED` the walk makes no network call (`test_the_walk_boots_every_script_the_page_loads`) · `OWNER` the same discipline on the hands-on pass |
| turning production execution on | `OWNER` after this validation (HANDOFF §6) |

## E. At scale (§13.1, §7)

Runnable only once a deployment exists. The multi-shard production flip stays the owner's, after these are green.

| Criterion | Check |
|---|---|
| a first acceptance run at 100,000 registered users | `OWNER` the S4 harness (`PENDING` S4, §4.4) |
| then 1,000,000 registered users | `OWNER` the S4 harness (`PENDING` S4) |
| 10,000 concurrent engagements | `OWNER` the S4 harness (`PENDING` S4) |
| p99 login and page latency under 500 ms | `OWNER` the S4 harness (`PENDING` S4) |
| the appends-per-second target, from S1's measurement at that load | `OWNER` (`PENDING` S1) |
| the multi-shard production flip | `OWNER` after S4 is green |

---

## Sign-off

Gate 5 is signed when every `AUTOMATED` row is green on the branch under test, every `PENDING` row has merged and
turned green, and every `OWNER` row has been performed on a real deployment with its evidence attached.

| Sign-off | Name | Date | Evidence |
|---|---|---|---|
| `AUTOMATED` the walk, green on the branch under test | | | the census JSON and the `test_gate5_customer_e2e.py` run |
| `OWNER` the hands-on journey | | | Stripe test-mode receipts, the webhook log, the statement against the ledger |
| `OWNER` at scale (S4) | | | the S4 run report |
