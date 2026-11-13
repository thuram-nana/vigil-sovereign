# VIGIL products, pricing, metering and Red-Pen — design and owner decisions

Status: **a proposed pricing model, not yet a validated profitable rate** (the owner's words, 2026-11-11). The owner
confirmed the credit rate, the minimum, the packs, the single model, the effort-by-depth rule, the customer-facing
name, the shared-API-key model and the Red-Pen product (§1). Every OTHER number in this document — the markup, the
floor, the tier budgets, the purchase limits, the concurrency limits — is the design's researched **proposal, not an
owner decision** (§1.2 lists what is still open). Each is a code default with an env override behind a default-OFF
flag, so the owner can change any of them without a release. Nothing here is live until its flag is turned on.

## 1. What the owner decided

| Decision | Value |
|---|---|
| Credit rate | 100 credits per $1 (1 credit = $0.01 at list) |
| Minimum purchase | $5 |
| Packs | $5, $10, $16, $25, $50, $100 → 500, 1,000, 1,600, 2,500, 5,000, 10,000 credits. No volume bonus |
| Custom amount | from $5, whole dollars × 100 credits (one conversion rate, no volume bonus); the maximum in §4.6 is a proposal |
| Unused credits | unused purchased credits are retained |
| Model | one model, Claude Opus 4.8, for every run |
| Depth | each depth runs at an effort level: high, xhigh or max |
| Ultracode | the Max tier: multi-agent orchestration at max effort, for live systems as well as code, and for fixing code |
| Name customers see | **VIGIL**. The model is never named on a customer surface |
| One API key | VIGIL buys tokens on its own Anthropic account; every tenant's runs draw on that one key; each tenant sees only their own bill, in credits |
| Who tests what | some customers test live deployed systems, some test code, some both |
| Fixing is optional | some customers only want to know their vulnerabilities; VIGIL fixes only when asked |
| Red-Pen | the repo's own adversarial review becomes a customer feature for PRs and whole systems |
| Fairness | tenants must get the work they paid for, and VIGIL must keep a healthy margin |
| At launch | pay-as-you-go credits, per-host AEGIS subscriptions, quoted enterprise contracts. Discounted credit subscriptions only after costs are measured |

### 1.1 Owner input of 2026-11-11 (given after the first draft of this design)

- **Confirmed:** $1 = 100 credits; packs $5 / $10 / $16 / $25 / $50 / $100 for 500 / 1,000 / 1,600 / 2,500 / 5,000 /
  10,000 credits; custom amounts from $5 at dollars × 100; one conversion rate, no volume bonus; unused purchased
  credits are retained.
- **Pricing principle (the owner's words):** "price scan consumption according to actual operating cost. This is a
  proposed pricing model, not yet a validated profitable rate." The costs to count are **AI usage, scan workers,
  storage and payment processing**. A credit must **not** promise a fixed number of raw tokens; deeper scans and more
  expensive models consume more credits.
- **Margin:** superseded by the decision below.
- **Customer experience:** show the credits received immediately when an amount is entered; before a scan show the
  estimated consumption and let the customer set a maximum credit budget; during the scan show consumption and the
  remaining budget; at completion charge the metered usage and release the unused reserved credits; optional automatic
  top-up with a spending cap.
- **Launch offer:** pay-as-you-go credits, separate per-host AEGIS monitoring subscriptions, quoted enterprise /
  on-premise contracts; discounted credit subscriptions only after real scan costs are measured.

### 1.1a Owner decisions of 2026-11-11 (later the same day)

- **Margin:** every scan is priced at an **owner-set target margin over its direct cost** (superseded 2026-11-13: the
  margin is over the **metered AI cost only** — see "One pricing number" below) (recorded privately,
  outside this public repository). It is applied through `VIGIL_BILLING_TARGET_MARGIN` at deploy, which has **no
  default in the code**: while it is unset or invalid, metered pricing stays off (every metered path fails closed).
  Calibration (M5) measures every direct cost (§1.2 c).
- **One pricing number (2026-11-13):** the target margin is the margin over the run's **metered AI cost only** (the
  model requests the gateway meters); payment fees, hosting and workers are outside it, so the all-in margin is
  lower. It is the only pricing input: the margin dashboard's target line is drawn from it, and the earlier knobs
  `VIGIL_BILLING_MARKUP_K` / `VIGIL_MARGIN_MULTIPLIER_K` are refused while present (`vigil doctor` reports a hard
  issue; metered launches refuse and metered charges wait).
- **Seats:** $25 per seat (assumed per month). Whether a seat includes credits is open.
- **Free trial:** a real scan that shows partial results; the full report unlocks once the organisation buys credits
  (any pack, from $5). One trial per verified email AND per verified domain. Ownership proof is still required
  (paying is not authority to test). Designed separately; not built here.
- **Audience:** young startups first — no minimums; packs from $5.
- Unchanged: $1 = 100 credits, packs $5–$100, custom from $5, no volume bonus, credits never expire, an estimate first
  and a customer-set budget.

### 1.2 Open owner decisions (none of these is ratified)

| # | Open item | State in the code |
|---|---|---|
| (a) | **The proposed numbers**: the 25-credit floor, the tier budgets 450 / 5,000 / 20,000, the top-up limits (§4.6), gateway concurrency 4 per tenant / 32 global. The owner has not confirmed any of them | env-overridable defaults behind default-OFF flags |
| (b) | **The margin value.** Decided by the owner (§1.1a) and set at deploy from the owner's private record; never committed | `VIGIL_BILLING_TARGET_MARGIN` (required, no default); `vigil doctor` flags metered billing without it (M1c) |
| (c) | **Cost basis.** The formula in §4.1 meters the **AI cost only**, and the target margin is the margin over that metered AI cost. The owner's profit target is measured **after all costs** (AI, card fees, hosting, workers, storage). Calibration (M5) reports the measured fee and hosting fraction per run, and the owner sets the target margin from it so the all-in margin lands on the target. There is no second pricing knob | not built; M5 |
| (d) | **Cancellation.** Whether a run the customer cancels is charged for the usage so far (this design's proposal, §4.4) or fully refunded. Decided by the owner (2026-11-13): a cancelled run pays for what it used, and a launch the customer paused and never resumed is charged the same way | `VIGIL_BILLING_CANCEL_SETTLEMENT` = `metered` (the default when unset) or `refund`; an unrecognised value refuses metered launches and defers cancelled-run settles, and `vigil doctor` reports it as a hard issue (M1c) |

## 2. The products

A customer makes three independent choices for every run.

### 2.1 What to test

| Target | What VIGIL does | How it is authorised |
|---|---|---|
| **Live system** — a deployed web app, API, host or cloud account | Tests it from outside (black-box), or with credentials the customer supplies (grey-box) | A current ownership proof (DNS TXT or HTTP file, existing `asset_ownership`) plus an owner-signed `EngagementAuthority` |
| **Code** — a repository | Reviews it from inside (white-box) in a sandboxed clone | The VIGIL GitHub App installed on the customer's own repository plus a repo-exact grant (existing PR-bot controls) |
| **Both** | Reads the code to aim the live tests, then proves each finding against the live system | Both of the above |
| **Every pull request** — Red-Pen · PR | Reviews each PR's diff and the code it touches | The GitHub App, as for code |

### 2.2 How deep

| Customer sees | Effort | How it works |
|---|---|---|
| **VIGIL · Quick** | high | One agent, focused on the most likely weaknesses. The cheapest useful run |
| **VIGIL · Deep** | xhigh | One long-running agent covering every surface the target has (the coverage table in `engine/crucible/CLAUDE.md` §V) |
| **VIGIL · Max** | max, with ultracode | Many agents in parallel, one per attack class, each finding attacked by an independent verifier before it is reported (§6) |

### 2.3 What the customer wants back

| Outcome | Included? | Live system | Code |
|---|---|---|---|
| **Find and prove** — verified findings with evidence, severity, plain-language impact, how to fix it, and a coverage map of what was and was not tested | always | yes | yes |
| **Fix** — VIGIL writes the patch, proves it works and opens a PR | opt-in, priced separately (§7) | not applicable | yes |
| **Retest** — re-run the proof of each finding the customer says they fixed: Verified Fixed / Still Vulnerable | opt-in, small | yes | yes |
| **AEGIS virtual patch** — block attacks on a finding inline while the customer fixes it | per-host subscription | yes | not applicable |

Fix never runs unless the customer asks for it, per finding or for all of them, and approves its estimate. A customer
who only wants to know their vulnerabilities gets a complete, proven report and is never charged for fixing.

## 3. Getting the work you paid for

| Commitment | How it is kept |
|---|---|
| **Know the price first** | Before any run the customer sees an estimate (typical cost and range, from calibration §9 M5) and what that depth covers, and sets a budget. The default budget is the tier's 90th-percentile cost, rounded up to 50 credits |
| **No money for a run that cannot work** | A free **preflight** runs before credits are reserved: the target is reachable, the ownership proof is current, the supplied credentials log in, the repository clones. It makes no model calls |
| **Always a report** | 10% of the budget is held back for the report. When the run reaches 90% of its budget the engine stops testing and writes up what it found, so a budget-limited run still delivers its findings and its coverage map |
| **Never pay twice for the same ground** | A run that reached its budget can be **continued** with more credits; it resumes from where it stopped (Strix `--resume`), it does not start over |
| **Our failures are free** | A run that fails on VIGIL's side (infrastructure, provider errors after retries, an engine crash) is charged nothing and is retried once automatically |
| **Only proven findings** | A reported finding carries a reproduction or a deterministic oracle's signed certificate. Unproven suspicions are shown separately as leads and never counted as findings |
| **An honest coverage map** | Every report says which surfaces were tested and which were not, and why |
| **One bill, in credits** | The customer sees credits bought, credits used per run, credits released and the balance. They never see tokens, the model or VIGIL's costs (§5.4) |

## 4. The money model

### 4.1 What a run costs the customer

```
charge_credits = min(reservation, max(FLOOR, ceil(cost_usd / (1 − target_margin) × 100)))
```

- `cost_usd` is computed on the sovereign side by the model gateway (§5) from the usage Anthropic reports on every
  response it forwards, priced with the cost table (§4.2). It is never an amount the offense plane reports, and never
  the agent runtime's client-side estimate.
- `target_margin` (`VIGIL_BILLING_TARGET_MARGIN`, a decimal strictly between 0 and 1) is the owner's margin over the
  metered AI cost only, set at deploy; the code has no default and refuses to price without it. **FLOOR = 25 credits** ($0.25) per run, covering worker
  start-up (`VIGIL_RUN_FLOOR_CREDITS`), is a **proposed default, not owner-confirmed** (§1.2 a).
- `cost_usd` is today the AI cost only. Workers, storage and payment processing are direct costs too; the target
  margin is set (from M5's measured fractions) so the all-in margin covers them (§1.2 c).
- The charge never exceeds the reservation the customer approved.

Because the charge follows the cost, a run that is cheaper or dearer than estimated is charged
in proportion; caching makes a run cheaper for the customer too.

Cash flow is positive by design: a customer pays for credits before any run draws on VIGIL's Anthropic balance, and
the gateway reserves each request's worst case (input and output) against the run's cap before it is sent (§5.1).
The cap is enforced from the provider's own token count, which is an estimate: the residue past it is VIGIL's cost,
never the customer's.

### 4.2 Cost table

Claude Opus 4.8 (`vigil_core.model_metering.DEFAULT_PRICES`; owner override `VIGIL_MODEL_PRICES`): per million
tokens, input $5.00, output $25.00, cache read $0.50, 5-minute cache write $6.25, 1-hour cache write $10.00; web
search $10 per 1,000 searches. Money is integer nano-USD; a price finer than $0.001 per million tokens is refused,
never rounded.

A credit therefore buys a different number of tokens depending on their kind: an output token costs five times an
uncached input token and fifty times a cached one. That is why a credit is not a fixed number of tokens.

**Two existing defects this replaces:**
- `credit_lease.ENVELOPE_TOKENS_PER_CREDIT = 100_000` sells a million tokens for $0.10 while they cost about $2
  blended. Every run would sell at ~5% of its AI cost.
- `vendor/strix/strix/report/anthropic_pricing.py` matches `claude-opus-4-8` to the Opus 4 row ($15/$75, three times
  the real $5/$25). A budget cap computed from it stops a run at a third of what the customer paid for.

### 4.3 Reservation, live meter and settle

1. The customer sets a budget; it is reserved from the wallet. The run's model grant (§5.1) caps its AI spend at
   `floor(budget × $0.01 / markup)`, where `markup = 1 / (1 − target margin)` (`model_metering.billing_markup`).
2. During the run the customer sees credits used and credits left, read from the gateway's meter.
3. At completion the meter is closed and the run settles at `charge_credits`; the rest of the reservation is released.
   The meter cannot be closed while one of the run's requests is still in flight (the settle retries), so the total
   it settles on is never missing a response. Spend the meter must assume but cannot prove — a request whose record
   was lost to a crash, the unreported part of a cut-off response — is recorded as **unconfirmed**: it counts against
   the run's cap and is VIGIL's cost, never the customer's.

### 4.4 Outcomes

| Outcome | Charge |
|---|---|
| Completed | metered |
| Budget reached | metered (= the reservation); findings and coverage delivered; can be continued |
| Cancelled by the customer | **OPEN OWNER DECISION (§1.2 d).** Proposed: metered for what was used (at least the floor). Today a cancel is a full refund, so a run taken to 95% and cancelled is free. The policy is a named setting; nothing is decided until the owner chooses |
| Target unreachable mid-run (the customer's side) | metered for what was used; the preflight makes this rare |
| Failed on VIGIL's side | 0, and retried once |

### 4.5 Default budgets (before calibration)

A budget is the most a run may charge, in credits ($1 = 100 credits); what a run typically charges comes from
calibration (M5). **These budgets are proposals, not owner-confirmed (§1.2 a).**

| Run | Default budget (the cap) | Note |
|---|---|---|
| Quick (live or code) | 450 credits ($4.50) | fits the $5 pack |
| Deep | 5,000 credits ($50) | |
| Max (ultracode) | 20,000 credits ($200) | bought with a custom top-up or invoice |
| Red-Pen · PR | 300 credits per PR, with a monthly cap per repository | |
| Fix, per finding | 2,000 credits | estimate shown before it starts |
| Retest, per finding | 200 credits | |

Quick is capped at 450 credits so the smallest purchase always covers one Quick run. If calibration shows a useful
Quick run does not fit, the cap is revisited and the UI says the $10 pack is the entry point.

### 4.6 Purchase limits

Proposed, not owner-confirmed (§1.2 a). The owner confirmed only the $5 minimum and the dollars × 100 rate.

| Limit | Value | Why |
|---|---|---|
| Custom amount | $5 – **$500** per purchase | Anthropic itself caps a Tier-1 credit purchase at $500 |
| First purchase on a new account | ≤ $100 | until the account has ≥ $100 of settled purchases and is ≥ 7 days old |
| Per account per 24 h | ≤ $1,000 | a stolen card's credits are spent on AI cost VIGIL cannot recover |
| Purchase attempts | ≤ 5 per hour per account | card testing uses many small attempts |
| Above $500 | invoice (enterprise) | cheaper fees, no card risk |

### 4.7 Auto top-up (later slice)

Off by default; optional, **with a spending cap** (owner, §1.1). The customer sets a trigger balance, a pack and a
monthly cap; it uses a tokenised card, never exceeds the cap, and emails a receipt each time.

## 5. One API key, many tenants

VIGIL holds one Anthropic API key. Every tenant's runs draw on it; each tenant sees only their own bill.

### 5.1 The model gateway

The settle signal the offense plane sends at the end of a run deliberately carries no amount
(`vigil_core/engagement_completion.py`): the keyless offense plane must never be able to set a charge. Metering keeps
that property by happening on the sovereign side. Every model request of a customer run goes through the sovereign
**model gateway** (`sigil/model_gateway.py`), an Anthropic Messages API reverse proxy on loopback:

- **It holds the key.** The offense plane never sees it. Each run gets an owner-signed **model grant**
  (`vigil_core/model_grant.py`) bound to the tenant, the launch, the model, the effort, a USD cap and an expiry; the
  runners present it as their API key, with the gateway as their base URL (Strix `LLM_API_BASE`, Claude Code
  `ANTHROPIC_BASE_URL`). The key only travels over TLS, never follows a redirect, and is never logged.
- **It forwards only what the meter can price — an allowlist.** The grant's model only. A known set of request fields;
  anything else is refused by name. An allowlist of content-block types, checked wherever blocks are nested: every
  server-tool block (a web-fetch result, a server tool call, an MCP block) and container uploads are refused. Images
  only inline (an image by URL would have Anthropic fetch an address the runner chose). Only tools the runner itself
  executes, by exact type (bash and the text editor): every tool Anthropic would run on its side is refused — web
  search and web fetch (a server-side loop whose input the request does not show), code execution (container time),
  the advisor tool (a second model's tokens), MCP (Anthropic connects to a URL the runner chose) — as are server-side
  compaction and model fallbacks (billed outside the response's top-level usage), PDFs and file references (billed by
  pages, not by bytes), and unknown `anthropic-beta` values (dropped). **Consequence: a run cannot use Anthropic's web
  search through the gateway.** Re-enabling it needs its own reservation design.
- **It pins what changes a price.** `output_config.effort` is set to the grant's effort, which also delivers `max` to
  engines that cannot send it themselves. Thinking is set to adaptive (Opus 4.8 rejects `budget_tokens`); sampling
  parameters are dropped; fast mode and the priority tier can never reach the provider; inference is pinned to the
  global (standard-price) region; every cache write is the 5-minute kind (a 1-hour write costs twice the input
  price).
- **It reserves before it spends.** For each request the worst case is reserved against the run's cap before it is
  sent: its output (`max_tokens` × the output price, with `max_tokens` lowered to fit) and its input (an upper bound
  on its input tokens × the dearest input rate). The input bound is the request's size in bytes — a token is never
  shorter than a byte — plus an allowance per image; when that loose bound does not fit what is left of the budget,
  the provider's free token count gives the tight one (plus 5%, because the count is an estimate). The prompt-cache
  prefix the provider will read is reserved at the cache-read rate — an agent re-sends its whole context every turn,
  and reserving it as fresh input would stop a run at a fraction of its budget. The gateway gives that rate only
  when every condition the provider's cache depends on holds: the run wrote or read that prefix within the cache
  lifetime (less the longest the gateway can take to admit the request), re-sends it unchanged with the same request
  settings, betas and image count, has a cache breakpoint within the provider's 20-block reach of the entry, and uses
  no server-side context edits. Concurrent
  requests cannot jointly pass the cap. A request that does not fit only because another is still in flight waits,
  then gets a retryable error; so does one the gateway cannot size right now; a spent budget is a refusal.
- **It meters from a write-ahead record.** The launch's hash-chained meter file gets an `open` line before a request
  is sent and a `usage` or `release` line after. A crash in between leaves a record that the next gateway (or the
  settle) records as unconfirmed spend, counted against the cap and never billed. A meter that cannot be written
  refuses the request; a record that cannot be written after the call is retried, and the launch waits for it. A response whose usage the meter cannot read — or that reports a server-side step the price table does
  not cover — is charged its reservation, never run free.
- **It answers in Anthropic's error shape**, so the runners stop cleanly.

What it does not bound: the provider's bill is only known after the fact. If Anthropic bills a request more input
tokens than its own count said (beyond the 5% the gateway adds), or does not read a cache entry although every condition
above holds (an early eviction, or a cache rule the gateway does not model), the run passes its cap by that
difference.
That is VIGIL's cost; the settle clamps the customer's charge to the reservation.

### 5.2 Protecting VIGIL's account

| Risk | Control |
|---|---|
| One tenant takes all of VIGIL's rate limit | Per-tenant concurrency in the gateway (proposed default 4 in-flight requests; the `VIGIL_GATEWAY_TENANT_CONCURRENCY` knob is wired in M1c); a request over the limit waits briefly, then gets a `rate_limit_error` with `retry-after`, which the runners already back off on. Concurrency does not bound input tokens per minute: one tenant sending very large requests can still crowd the account's token-rate limit |
| All tenants together exceed the account's rate limit | A global concurrency cap (proposed default 32; `VIGIL_GATEWAY_GLOBAL_CONCURRENCY`, M1c), sized to the account's Anthropic tier; provider 429s are relayed with their `retry-after`. Open connections are bounded and every client socket has a deadline |
| A bug or an abuse drains the prepaid balance | A global daily spend ceiling in the gateway (`VIGIL_GATEWAY_DAILY_LIMIT_USD`, M1c; **unset means no ceiling** — `vigil doctor` notes it); plus a provider-side backstop: customer traffic runs in its own Anthropic **workspace** with a monthly spend limit set in the Console (owner action) |
| Traffic that bypasses the gateway | A daily reconciliation compares the gateway's totals with Anthropic's Usage and Cost Admin API for that workspace (needs an admin key; owner action) |
| The key leaks from the offense plane | It is never there: only grants are, each bounded by its run's cap and expiry |
| The Anthropic balance runs out | Customers prepay, so revenue arrives before cost. The owner enables auto-reload on the Anthropic account with a cap |
| Growth outruns the account's tier | Anthropic raises limits with cumulative purchases; at scale, an enterprise agreement or Priority Tier |

### 5.3 Tenant isolation on a shared key

- Each request carries only its own run's context; the gateway keeps no conversation state and no cross-run cache.
- Anthropic's prompt cache is scoped to VIGIL's workspace, not to a tenant, and matches only an identical prefix.
  Left alone, a tenant could learn whether another tenant had just sent a given prefix (a cache hit shows in the
  usage). The gateway therefore prepends a block unique to the tenant to every request's system prompt, so no cache
  entry at or after the system prompt can match across tenants. Tool definitions come before the system prompt in
  the cache order and stay shared: they must be tenant-independent (they are VIGIL's own).
- The meter is per launch and keyed by the owner-signed `(engagement, nonce)`, so one tenant's spend can never land on
  another's bill.
- Data handling is disclosed: Anthropic retains API inputs and outputs for a limited period under its commercial terms
  and does not train on them; zero-data-retention is an enterprise-contract option. The sub-processor list names
  Anthropic (GDPR Art. 28).

### 5.4 Two views of the same money

| The tenant sees | The owner sees |
|---|---|
| Credits bought (with invoices), credits used per run (target, depth, start, end, findings, credits charged and released), balance, monthly statement | Per tenant and per run: revenue, AI cost from the gateway, margin; daily gateway total against Anthropic's own usage report |
| Never: tokens, the model, VIGIL's cost | Everything |

## 6. Max (ultracode) on live systems and on code

Max runs many agents in parallel. That changes what has to be controlled.

**On a live system** more agents must never mean more load on the customer's production:
- All target traffic leaves through VIGIL's scope-gated egress proxy (`gateway/vigil_gateway`): only proven hosts, and
  **one rate limit and one connection cap per engagement, however many agents run** (default 10 requests per second
  and 8 connections; the customer can lower or raise it in the engagement charter).
- The agents have no raw shell and no network of their own: their only tools are VIGIL's governed tools (the same
  governed executor Strix uses — scope check, WARDEN tier, owner approval for anything destructive). Orchestration can
  never bypass the gates.
- The constitution's hard stops apply to the run, not to each agent: a 5xx storm or rising latency throttles and then
  pauses the engagement; evidence of a prior compromise stops testing and switches to incident response.
- Traffic is correlatable: a stable egress IP and a VIGIL User-Agent the customer can find in their logs.
- The customer and the owner can halt it at once (the kill switch).

**On code** the agents work in a sandboxed clone with no network except the model gateway, and no secrets.

**For fixing** (VIGIL Fix): Claude Code with `--effort max --settings '{"ultracode": true}'` (Claude Code v2.1.284 or
later; the `Workflow` tool allowed for headless runs), in the sandbox clone, then the re-review in §7.2.

Ultracode is a Claude Code setting, so Max runs use Claude Code headless through the Agent SDK on VIGIL's API key; the
Agent SDK terms do not allow a claude.ai subscription to power a product for customers. VIGIL keeps its own branding:
"Claude Code" and "ultracode" never appear to customers.

## 7. Red-Pen and Fix

### 7.1 What Red-Pen is

In this repo every build stream must pass RED-PEN (`engine/crucible/.claude/agents/red-pen.md`): an adversarial
reviewer that tries to break the change and either blocks it with concrete objections or attests what it attacked and
why it held. After a single RED-PEN pass missed two critical defects (B3), the merge bar became a **dual review**:
RED-PEN plus an independent multi-lens sweep, where each lens attacks and each objection is then confirmed or refuted
with a real reproduction. Red-Pen offers that bar to customers:

- **Red-Pen · PR** — every pull request on a connected repository.
- **Red-Pen · System** — a whole repository, on demand or on a schedule.

VIGIL already has the pieces Red-Pen stands on: the GitHub webhook route and job queue, the PR bot
(`integration/vigil_integration/jobs/pr_bot.py`: diff scan → oracle-verified findings → gated review comments → gated
fix-PR leg), the PR-head checkout (`live/pr_checkout.py`), the codefix runner (`live/codefix_runner.py`) and the S5
sandbox. Red-Pen adds the adversarial review engine and wires it in.

### 7.2 Pipeline

1. **Map.** Threat-model the diff or the system: entry points, trust boundaries, data flows.
2. **Attack.** Independent lens agents, one per lens: authentication and authorisation, injection, crypto and secrets,
   business logic, data exposure, SSRF and egress, deserialisation, concurrency and races, supply chain and CI,
   infrastructure-as-code and cloud, LLM and prompt injection, and test honesty (tests that pass without testing what
   they claim). Each returns candidates with file and line and a proposed reproduction.
3. **Refute each.** For every candidate a separate verifier tries to disprove it and must produce a reproduction that
   runs in the sandbox — a failing test or a proof of concept against the customer's own build. A candidate survives
   only if its reproduction fails on the reviewed commit, twice, and the verifier could not refute it.
4. **Certify.** A reproduced candidate goes through the existing veracity firewall
   (`oracle_adapter.confirm_and_certify(..., provenance="reproduced")`) and becomes a signed FACT. Everything else
   stays a LEAD.
5. **Report.** Each FACT is posted as a PR review comment through the existing gated `post_review_comment`, marked
   🔴 Critical / High (blocking), 🟠 Medium or 🟡 Low, with the reproduction command and the evidence ref, and a
   **Fix this** action. A LEAD is never posted as a finding; leads appear in the dashboard for the customer to triage.
6. **Fix, only when asked.** For a FACT the customer chose to fix: the patch is written (§6), then re-reviewed — the
   reproduction now passes, the full test suite passes, and a Quick Red-Pen of the patch's diff finds no new FACT.
   Only then does the gated fix-PR leg open a PR, with the customer's approval. A finding is "remediated" only when its
   reproduction or oracle goes silent (the existing rule).

### 7.3 Authorisation and safety

- A repository is connected through the GitHub App on the customer's own repository plus a repo-exact grant. Review
  uses a read-only token; commenting and opening PRs are separate grants, each approved.
- Defensive only: reproductions run against the customer's own code in the sandbox, never against a third party.
- PR code is hostile input: fenced against prompt injection (`render_untrusted_finding`, the nonce fence); the agent
  runs with no secrets; the workdir is confined and destroyed after the job.

### 7.4 Price

Metered like every run, with the same markup, and the defaults in §4.5. The PR default is Quick with a cap per PR
and a monthly cap per repository.

## 8. Risks stated plainly

- **Multi-agent runs spend many tokens.** The gateway reserves every request against the cap and the estimate is shown first, but a customer's
  first Max run may still cost more than they expected. The UI must make the estimate and the budget unmissable.
- **Ultracode is new** (it launched with Opus 4.8 in May 2026) and its behaviour can change. Pin the Claude Code
  version and re-calibrate when it moves.
- **Opus 4.8 vs Opus 5 / 5.5.** Opus 5 costs the same and Opus 5.5 costs 20% less, but both add elevated cybersecurity
  safeguards that can refuse security work. Staying on 4.8 is the safer launch choice; an eval on the CRUCIBLE corpus
  should compare refusal rate and finding yield before any switch.
- **The gateway is on the path of every model request.** It streams without buffering; at Front C scale it becomes
  its own service. Until then a gateway outage stops customer runs (fail-closed) and never bills them.
- **Payment and infrastructure costs are assumptions** until measured (§1.2 c).

## 9. Build order

Serial PR queue; each slice is default-OFF, tested both ways, mutation-checked and red-penned before merge.

| Slice | What |
|---|---|
| M1 | Metering core (`vigil_core.model_metering`, `vigil_core.model_grant`) and the sovereign model gateway (§5.1, §5.2): grant auth, the request allowlist and pinning, the reserved budget (input and output), the write-ahead per-launch meter, tenant and global concurrency, daily ceiling, the budget read for the live meter |
| M1c | Wiring: the launch mints the grant and publishes its token on the seam; Strix and Claude Code run through the gateway; settle = metered (§4.3, §4.4) behind `VIGIL_METERED_BILLING`; the Strix price-table fix; a `vigil doctor` line |
| M2 | Engine: the 90% wrap-up for the report reserve; `max` through Strix with a wire test; runtime caps from the grant as a second line of defence; continue = resume |
| M3 | Catalog: the six packs and custom top-ups ($5–$500, the §4.6 limits), no bonus; the placeholder catalog retired |
| M4 | Customer UX: the VIGIL naming sweep and the no-model-id test; target / depth / outcome choice; preflight; estimate, budget, live meter; the tenant statement (§5.4) |
| M5 | Calibration: each tier N times against the loopback range and the CRUCIBLE corpus; the 10th / 50th / 90th percentiles become the estimates. It must also measure **worker and storage cost per run** (or derive an overhead factor) and report the measured fee and hosting fraction per run, from which the owner sets the target margin so the all-in margin lands on the target (§1.2 c). Needs the owner's API key and a spend approval |
| L1 | Live Max: one rate limit and connection cap per engagement at the egress proxy; agents on governed tools only; run-level hard stops |
| R1 | Red-Pen engine: the workflows, the sandbox reproduction runner, certification through the oracle adapter |
| R2 | Red-Pen · PR through the PR bot, with the severity marks and the **Fix this** action |
| R3 | Red-Pen · System |
| R4 | VIGIL Fix (opt-in) and Retest |
| R5 | Red-Pen, Fix and Retest in the customer UI |
| O1 | Owner money view: per-tenant cost and margin from the gateway; the Admin-API reconciliation |
| A1 | Auto top-up |

Owner-only items: the API key in the secret store (and a dedicated Anthropic workspace with a spend limit), an
Anthropic admin key for reconciliation, the Flutterwave live keys, the customer-facing GitHub App registration,
turning on each flag, and the calibration spend.

## 10. Sources

- Claude Opus 4.8 prices, effort levels and caching: Anthropic's model and prompt-caching documentation (the
  claude-api reference, 2026-11).
- Ultracode and dynamic workflows: https://code.claude.com/docs/en/model-config ,
  https://code.claude.com/docs/en/workflows , https://code.claude.com/docs/en/cli-reference
- Agent SDK authentication and branding rules: https://code.claude.com/docs/en/agent-sdk/overview
- Anthropic's own credit-purchase limits and tiers: https://platform.claude.com/docs/en/api/rate-limits
