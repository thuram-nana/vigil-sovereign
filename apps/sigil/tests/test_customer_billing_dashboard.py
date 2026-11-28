"""W6 / C5 — the customer app's Billing dashboard, behind VIGIL_CUSTOMER_BILLING_DASHBOARD (default OFF).

What these pin:
  * the edge writes data-billing-dashboard into the page (1 only while the flag is affirmative, 0 otherwise), the
    value counts in the build id, and __VIGIL_BILLING_DASHBOARD__ is never left unsubstituted;
  * FLAG OFF: viewBilling() renders exactly the pre-W6 screen (the Credits / Wallet / Subscription cards + Buy) and
    makes exactly the two reads it always made (billing, billing/offers) — byte-identical behaviour;
  * FLAG ON: the dashboard renders available credits, credits ON HOLD for running assessments, live consumption per
    running scan, the statement with each charge's rate + BALANCE-AFTER, the published Rates (loaded on demand), the
    low-balance notice (only when the server flags it) and the Auto top-up section; it adds exactly the billing/usage
    read (rates stays lazy) and reuses the existing Buy surface; "Credits bought" is the server's top-ups-only total
    (never the wallet's granted, which also counts refunds of unused reservations);
  * FLAG ON but no metered figures (metered billing off): the flat-billing cards exactly as the classic screen shows
    them, plus Rates / low-balance / Auto top-up, and NO usage read — usage lines are never presented as charges;
  * no estimate, no predicted total, no reserved unit count, no money amount for a scan and no model/engine name
    appears in any billing payload or in the rendered dashboard (credits are shown; that is the point).

guide.js's "Credits and plans" / "Statement and invoices" copy already names these controls (Rates, Auto top-up,
the statement, what is on hold); a test keeps the guide's words and the screen's real labels in step. #/billing is an
existing route, so the screen census stays green unchanged.

app.js's own functions are extracted VERBATIM and executed under node with a minimal DOM + the real UI kit; every
page-flag constant the extracted code could reference is stubbed off first (`var X = false;`).

Mutation-verify targets (each neuter reds a NAMED test here):
  * the app ignores the page flag (BILLING_DASHBOARD_ON const) -> test_flag_off_is_the_classic_screen_and_reads
  * the dashboard never fetches billing/usage                  -> test_flag_on_renders_the_dashboard_and_adds_the_usage_read
  * the held / bought / balance-after / running-scan guards hide a field
                                                               -> test_flag_on_renders_the_dashboard_and_adds_the_usage_read
  * the metered sections render without the exact figures      -> test_flag_on_without_metered_figures_shows_the_flat_billing_cards
  * mc2 does not round the balance DOWN                        -> test_the_balance_is_shown_to_two_decimals_rounded_down
  * the low-balance notice shows without the server's flag     -> test_the_low_balance_notice_only_shows_when_flagged
  * the auto top-up settings never render                      -> test_the_auto_topup_settings_render_when_a1_supplies_them
  * an estimate / a model name in the dashboard copy           -> test_no_model_id_money_or_estimate_in_payloads_or_the_rendered_dashboard
  * the Rates control no longer matches the guide's words      -> test_the_guide_names_the_dashboards_real_labels
  * the edge always writes "1"                                 -> test_the_edge_writes_the_dashboard_flag_into_the_page
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from test_customer_onboarding import _DOM, _guide, _need_node, _page_and_build  # noqa: F401  (reuse DOM/edge/guide)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS = APP / "ui.js", APP / "app.js"

# model / engine ids, a money sign, a bare "usd", or an "estimat*" — none may appear on a customer billing surface
# (the rate-conversion constant credits_per_usd is stripped before scanning). A credit AMOUNT is allowed and expected.
_LEAK = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b"
                   r"|[$€£]|\busd\b|estimat|predict|forecast|projected", re.IGNORECASE)


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    """One of app.js's multi-line functions, verbatim (the harness runs what ships, not a copy)."""
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def _line(src: str, pattern: str) -> str:
    m = re.search(pattern, src, re.M)
    assert m, f"app.js no longer has a line matching {pattern!r}"
    return m.group(0)


# the pure render functions (no fetch); `h` is the kit's own, kv/fmtDate are app.js's own. autoTopupSection renders
# its card + the on-demand control synchronously (the fetch + form are behind its button, like ratesSection); the
# form's own render helpers are pure too.
_RENDER = ["kv", "fmtDate", "mc2", "groupInt", "billingCreditsCard", "billingSubscriptionCard",
           "lowBalanceNotice", "billingUsageView", "billingUsageCard", "runningScansCard", "statementCard",
           "chargeRow", "rateText", "shortId", "ratesList", "rateRow", "perPhrase", "autoTopupSection",
           "autoTopupForm", "autoTopupReceiptRow", "autoTopupStatusText", "autoTopupUnavailableText"]
# the fetch-wiring functions on top of the render set (saveAutoTopup posts the change through the step-up seam)
_WIRING = ["pageFlag", "dataView", "buySection", "viewBilling", "viewBillingClassic", "classicBillingCards",
           "viewBillingDashboard", "loadBillingUsage", "ratesSection", "saveAutoTopup", "autoTopupInt"]

# sample server payloads (the real shapes: W1 rates, W2c-2 exact + balance-after, W6 per-scan running/held_mc)
_OV = {"org_id": "o", "credits": {"available": 57, "persistent": 57, "plan_live": 3},
       "wallet": {"granted": 70, "debited": 12, "available": 57}, "active": True,
       "subscription": {"plan_id": "research", "status": "active", "allotment": 2000, "period_start": 0,
                        "period_end": 9e9}, "exact_available_mc": 57_875, "exact_available": 57, "low_balance": True}
_USAGE = {"org_id": "o", "currency": "credits", "credits": "2.502", "amount_mc": 2502, "count": 1,
          "held_mc": 7_498, "available_to_start_mc": 50_377, "remaining_mc": 57_875,
          "bought_mc": 50_000, "trial_mc": 20_000,
          "scans": [{"scan": "cust_5b027ea557ffed11da0e29b3longid", "launch": "n1", "started_at": 1000,
                     "status": "ok", "requests": 1, "credits": "2.502", "amount_mc": 2502,
                     "running": True, "held_mc": 7_498}],
          "charges": [{"ts": 1_700_000_000, "scan": "cust_5b027ea5", "launch": "n1", "operation": "AI analysis",
                       "lines": [{"unit": "output_tokens", "label": "AI output tokens", "quantity": 400,
                                  "rate": "6250.000", "rate_per": 1_000_000, "credits": "2.500", "amount_mc": 2500},
                                 {"unit": "web_searches", "label": "Web searches", "quantity": 3, "rate": "2.500",
                                  "rate_per": 1, "credits": "7.500", "amount_mc": 7500}],
                       "credits": "2.502", "amount_mc": 2502, "balance_after_mc": 57_875}]}
_RATES = {"currency": "credits", "credits_per_usd": 100,
          "ai": [{"unit": "input_tokens", "label": "AI input tokens", "credits": "1250.000", "per": 1_000_000},
                 {"unit": "output_tokens", "label": "AI output tokens", "credits": "6250.000", "per": 1_000_000},
                 {"unit": "web_searches", "label": "Web searches", "credits": "2.500", "per": 1}],
          "worker": {"unit": "worker_minutes", "label": "Scan-worker time", "credits": "1.000", "per": "minute"},
          "premium": []}


def _flag_stubs(src: str) -> str:
    """`var X = false;` for every page-flag constant extracted app.js code could reference — the known ones plus every
    module-level `var <NAME>_ON =` app.js declares (so a flag another slice adds never throws a ReferenceError here).
    Code under test that needs its OWN flag re-assigns it afterwards (a later `var` assignment wins)."""
    names = {"GUIDE_ON", "SECURITY_ON", "TEAM_ON", "MONITORING_ON", "LAUNCH_ON", "BILLING_DASHBOARD_ON"}
    names |= set(re.findall(r"^  var ([A-Z][A-Z0-9_]*_ON) = ", src, re.M))
    return "".join(f"var {n} = false;\n" for n in sorted(names))


def _node(fns: str, scenario: str, *, is_async: bool = False) -> dict:
    head = (_DOM + f"\nrequire({json.dumps(str(UI_JS))});\nconst VUI = window.VUI;\nconst h = VUI.h;\n"
            + _flag_stubs(_js()) + fns + "\nconst out = {};\n")
    if is_async:
        prog = (head + "const tick = () => new Promise(r => setTimeout(r, 0));\n(async () => {\n" + scenario
                + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
                " e => { console.error(e && e.stack || e); process.exit(3); });")
    else:
        prog = head + scenario + "\nprocess.stdout.write(JSON.stringify(out));"
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _render_fns() -> str:
    src = _js()
    return "\n".join(_fn(src, n) for n in _RENDER)


def _wiring_fns(flag: str) -> str:
    """The render set + the fetch-wiring set + the module flag line, with the page flag set and the app's shell /
    navigation / loading stubbed so the billing views can run in isolation."""
    src = _js()
    stubs = ("function here(){ return '#/billing'; }\nfunction loadingHolder(t){ return h('p.cust-muted', {text:t}); }\n"
             "function shell(inner){ return inner; }\nfunction err(m){ out.err = m; }\nfunction nav(){}\nasync function refreshWho(){}\n"
             "function withStepUp(action){ return action(); }\n")   # security screens off in the harness: step-up is a pass-through
    return "\n".join([f"document.body.dataset.billingDashboard = {json.dumps(flag)};",
                      _render_fns(),
                      "\n".join(_fn(src, n) for n in _WIRING),
                      _line(src, r'^  var API = "[^"]*";'),
                      _line(src, r"^  var BILLING_DASHBOARD_ON = .*;$"),
                      stubs])


# --- the edge flag ----------------------------------------------------------------------------------------------

def test_the_edge_writes_the_dashboard_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_BILLING_DASHBOARD", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-billing-dashboard="0"' in off and "__VIGIL_BILLING_DASHBOARD__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_BILLING_DASHBOARD", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-billing-dashboard="1"' in on and build_on != build_off      # the value counts in the build id
    # the flag is the page's ONLY difference (besides the build id it feeds): the same app, byte for byte
    assert on.replace('data-billing-dashboard="1"', 'data-billing-dashboard="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_BILLING_DASHBOARD", v)
        assert 'data-billing-dashboard="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


# --- flag off: byte-identical behaviour -------------------------------------------------------------------------

def test_flag_off_is_the_classic_screen_and_reads():
    out = _node(_wiring_fns("0"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p);
  if (/\/billing\/offers$/.test(p)) { const e = new Error('off'); e.status = 404; throw e; }
  return """ + json.dumps(_OV) + r"""; };
const node = viewBilling(); document.body.appendChild(node);
await tick(); await tick();
out.calls = calls; out.text = node.textContent;
""", is_async=True)
    # exactly the two reads the classic screen always made — no billing/usage, no billing/rates
    assert out["calls"] == ["api/customer/billing", "api/customer/billing/offers"]
    # the classic cards, unchanged
    assert "Persistent (wallet)" in out["text"] and "Granted" in out["text"] and "Debited" in out["text"]
    # none of the dashboard-only sections
    for gone in ("On hold for running assessments", "Statement", "Auto top-up", "Credits bought"):
        assert gone not in out["text"], gone


def test_the_route_and_classic_body_are_unchanged():
    src = _js()
    assert '"#/billing": function () { return authed() ? viewBilling() : viewLogin(); }' in src
    assert "return BILLING_DASHBOARD_ON ? viewBillingDashboard() : viewBillingClassic();" in src
    assert 'dataView("#/billing", "Billing", API + "/billing", classicBillingCards)' in _fn(src, "viewBillingClassic")
    classic = _fn(src, "classicBillingCards")
    for lbl in ('VUI.card("Credits"', 'VUI.card("Wallet"', 'VUI.card("Subscription"', "buySection()"):
        assert lbl in classic


# --- flag on: the dashboard -------------------------------------------------------------------------------------

def test_flag_on_renders_the_dashboard_and_adds_the_usage_read():
    out = _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p);
  if (/\/billing\/usage$/.test(p)) return """ + json.dumps(_USAGE) + r""";
  if (/\/billing\/rates$/.test(p)) return { rates: """ + json.dumps(_RATES) + r""" };
  if (/\/billing\/offers$/.test(p)) { const e = new Error('off'); e.status = 404; throw e; }
  return """ + json.dumps(_OV) + r"""; };
const node = viewBilling(); document.body.appendChild(node);
await tick(); await tick();
out.calls = calls; out.text = node.textContent;
""", is_async=True)
    # the overview + the one new usage read; the Buy surface's offers read; RATES is lazy (not fetched yet)
    assert out["calls"] == ["api/customer/billing", "api/customer/billing/usage", "api/customer/billing/offers"]
    t = out["text"]                                                          # a kv row renders as label+value
    assert "Available57.87" in t                                             # the EXACT balance, rounded down
    assert "On hold for running assessments7.49" in t                        # held_mc (W2c-2 field)
    assert "Available to start work50.37" in t                               # available_to_start_mc
    assert "Credits bought50.00" in t and "Trial credits20.00" in t          # top-ups only; the trial apart (W6)
    assert "Credits used2.502" in t                                          # the metered total, exact
    assert "Running assessments" in t and "used 2.502" in t                 # per-scan live consumption (W6 field)
    assert "Statement" in t and "AI output tokens × 400" in t               # the statement, with the quantity
    assert "6250.000 per million" in t and "2.500 each" in t                # the per-line rate (tokens / per-one)
    assert "Balance after: 57.87 credits" in t                             # the per-charge balance-after (W2c-2)
    assert "Your balance is low." in t                                      # the low-balance notice (W5 field)
    assert "Auto top-up" in t and "Set up auto top-up" in t                  # A1 opt-in control (its form is on demand)
    assert "Rates" in t                                                      # the on-demand Rates control
    assert "Persistent (wallet)" not in t and "Granted" not in t            # not the flat-billing cards


def test_flag_on_without_metered_figures_shows_the_flat_billing_cards():
    """With metered billing off the server sends no exact balance, and the usage record's lines were never charged
    (launches settle flat): the dashboard then shows the flat-billing cards exactly as the classic screen does, plus
    the published Rates, the low-balance notice and Auto top-up — and makes NO usage read."""
    flat = {k: v for k, v in _OV.items() if k not in ("exact_available_mc", "exact_available")}
    out = _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p);
  if (/\/billing\/offers$/.test(p)) { const e = new Error('off'); e.status = 404; throw e; }
  if (/\/billing\/usage$/.test(p)) return """ + json.dumps(_USAGE) + r""";
  return """ + json.dumps(flat) + r"""; };
const node = viewBilling(); document.body.appendChild(node);
await tick(); await tick();
out.calls = calls; out.text = node.textContent;
""", is_async=True)
    assert out["calls"] == ["api/customer/billing", "api/customer/billing/offers"]   # no billing/usage read
    t = out["text"]
    assert "Persistent (wallet)" in t and "Granted70" in t and "Debited12" in t     # the flat-billing cards
    assert "Rates" in t and "Auto top-up" in t and "Your balance is low." in t       # what holds in either mode
    for gone in ("On hold for running assessments", "Statement", "Credits bought", "Credits used", "Balance after"):
        assert gone not in t, gone


def test_the_rates_control_loads_the_published_card_on_demand():
    out = _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p);
  if (/\/billing\/rates$/.test(p)) return { rates: """ + json.dumps(_RATES) + r""" };
  return {}; };
const sec = ratesSection(); document.body.appendChild(sec);
out.before = sec.textContent;
const btn = sec.querySelectorAll('button').filter(b => b.textContent === 'Rates')[0];
btn.click(); await tick(); await tick();
out.after = sec.textContent; out.calls = calls;
out.btnAfter = sec.querySelectorAll('button')[0].textContent;
""", is_async=True)
    assert "1250.000" not in out["before"]                                   # nothing shown until asked
    assert out["calls"] == ["api/customer/billing/rates"]                    # fetched once, only on the click
    assert "AI input tokens" in out["after"] and "1250.000 credits per million" in out["after"]
    assert "Scan-worker time" in out["after"] and "1.000 credits per minute" in out["after"]
    assert out["btnAfter"] == "Hide rates"                                   # the control toggles


def test_the_balance_is_shown_to_two_decimals_rounded_down():
    out = _node(_render_fns(), r"""
out.cases = [mc2(57875), mc2(57879), mc2(7498), mc2(0), mc2(1), mc2(999), mc2(null), mc2(undefined)];
out.available_exact = billingCreditsCard(""" + json.dumps(_OV) + r""").textContent;
""")
    # 57.875 -> 57.87 (never 57.88); 57.879 -> 57.87; 7.498 -> 7.49; 0.999 -> 0.99; missing -> "—"
    assert out["cases"] == ["57.87", "57.87", "7.49", "0.00", "0.00", "0.99", "—", "—"]
    assert "Available57.87" in out["available_exact"]                        # the exact balance, rounded down


# --- the leak scan (§11.9) --------------------------------------------------------------------------------------

def test_no_model_id_money_or_estimate_in_payloads_or_the_rendered_dashboard():
    # 1) every billing payload the dashboard reads (the rate-conversion constant credits_per_usd excluded)
    for payload in (_OV, _USAGE, _RATES):
        blob = json.dumps(payload).replace("credits_per_usd", "")
        assert not _LEAK.search(blob), (_LEAK.search(blob).group(0), payload)
    # 2) the fully rendered dashboard content (overview + usage + rates + low-balance + auto top-up)
    out = _node(_render_fns(), r"""
const root = h("div", {}, [
  lowBalanceNotice(""" + json.dumps(_OV) + r"""),
  billingCreditsCard(""" + json.dumps(_OV) + r"""),
  billingSubscriptionCard(""" + json.dumps(_OV) + r"""),
  billingUsageView(""" + json.dumps(_USAGE) + r"""),
  ratesList(""" + json.dumps(_RATES) + r"""),
  autoTopupSection(""" + json.dumps(_OV) + r"""),
]);
document.body.appendChild(root); out.text = root.textContent;
""")
    assert not _LEAK.search(out["text"]), _LEAK.search(out["text"]).group(0)
    assert not re.search(r"\bunits?\b", out["text"], re.IGNORECASE)         # no reserved unit count, ever
    # a credit amount IS shown (that is the dashboard's job) — prove the scan did not simply find empty text
    assert "credits" in out["text"] and "57.87" in out["text"]


# A1 — the SESSION org's auto top-up read (/billing/auto-topup): credits only, never a money amount. `settings` is
# None until the org opts in; `packs` are the offered top-ups; `receipts` are the per-crossing outcomes.
_AT_OFF = {"settings": None, "card_saved": False, "month_credits": 0,
           "packs": [{"price_id": "price_topup", "name": "Credit top-up", "credits": 50},
                     {"price_id": "price_topup_big", "name": "Bulk credits", "credits": 1000}],
           "receipts": []}
_AT_ON = {"settings": {"enabled": True, "trigger_credits": 25, "pack_price_id": "price_topup_big",
                       "monthly_cap_credits": 5000},
          "card_saved": True, "month_credits": 1000,
          "packs": _AT_OFF["packs"],
          "receipts": [{"status": "charged", "credits": 1000, "at": 1_700_000_000},
                       {"status": "cap_blocked", "credits": 1000, "at": 1_700_600_000}]}


def _open_auto_topup(payload: dict) -> dict:
    """Render the Auto top-up section, click its on-demand control and return the loaded form's text + the reads."""
    return _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p); return """ + json.dumps(payload) + r"""; };
const sec = autoTopupSection(); document.body.appendChild(sec);
out.before = sec.textContent;
const open = sec.querySelectorAll('button').filter(b => b.textContent === 'Set up auto top-up')[0];
open.click(); await tick(); await tick();
out.after = sec.textContent; out.calls = calls;
out.toggle = sec.querySelectorAll('button')[0].textContent;
""", is_async=True)


def test_the_auto_topup_control_is_on_demand_and_opt_in_default_off():
    """The section is the one card every mode shows; its form loads on demand (like Rates) and, with no settings yet,
    the opt-in is OFF — an explicit choice, never defaulted on. The offered packs (credits only) are there to pick."""
    out = _open_auto_topup(_AT_OFF)
    assert "Set up auto top-up" in out["before"] and "coming soon" not in out["before"]   # off until opened
    assert "1250.000" not in out["before"]                                   # nothing fetched before the click
    assert out["calls"] == ["api/customer/billing/auto-topup"]               # the one read, only on the click
    t = out["after"]
    assert "Auto top-up" in t and "Off" in t                                 # default-off: not armed
    assert "Turn auto top-up on" in t and "Start when my balance falls below (credits)" in t
    assert "Credit top-up — 50 credits" in t and "Bulk credits — 1,000 credits" in t       # the offered packs
    assert "Buy credits once to save a card" in t                            # no card yet -> honest note
    assert out["toggle"] == "Hide auto top-up"                               # the control toggles closed again
    assert not _LEAK.search(t), _LEAK.search(t) and _LEAK.search(t).group(0)   # no money / model / estimate
    assert not re.search(r"\bunits?\b", t, re.IGNORECASE)                    # no reserved unit count


def test_the_auto_topup_form_shows_the_current_owner_signed_state():
    """Once armed, the form shows exactly the owner-signed state the server returns: On, the trigger, the pack it
    buys, the monthly limit, what was bought this month and the per-crossing receipts — credits only."""
    out = _open_auto_topup(_AT_ON)
    t = out["after"]
    assert "Auto top-up" in t and "On" in t                                  # armed
    assert "Bought this month" in t and "1,000 credits" in t                 # the month tally (cap usage)
    assert "Recent auto top-ups" in t and "Added credits" in t and "Held at your monthly limit" in t
    assert "Buy credits once to save a card" not in t                        # a card is saved -> no note
    assert not _LEAK.search(t), _LEAK.search(t) and _LEAK.search(t).group(0)


def _save_auto_topup(check: bool) -> dict:
    """Open the form (no settings yet -> box default-off), optionally check the box, set the fields and Save once.
    Returns the single POST (method, path, body). One save per scenario — no re-mount race."""
    return _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(['GET', p]); return """ + json.dumps(_AT_OFF) + r"""; };
VUI.postJSON = async (p, b) => { calls.push(['POST', p, b]); return { ok: true }; };
VUI.toast = () => {};
const sec = autoTopupSection(); document.body.appendChild(sec);
sec.querySelectorAll('button').filter(b => b.textContent === 'Set up auto top-up')[0].click();
await tick(); await tick();
const inputs = sec.querySelectorAll('input');            // [enabled, trigger, cap] in document order
const select = sec.querySelectorAll('select')[0];
inputs[0].checked = """ + ("true" if check else "false") + r""";
inputs[1].value = '25'; inputs[2].value = '2000'; select.value = 'price_topup_big';
sec.querySelectorAll('button').filter(b => b.textContent === 'Save auto top-up')[0].click();
await tick(); await tick();
out.posts = calls.filter(c => c[0] === 'POST');
""", is_async=True)


def test_saving_auto_topup_sends_a_strict_boolean_opt_in_and_the_customers_choices():
    """The Save sends the customer's choices to the one SET route: the trigger / monthly limit as whole credits and
    the chosen pack, carrying NO org_id (the server binds it to the session) and NO money amount. The on/off is a
    STRICT boolean — a checked box is exactly ``True``, never a truthy string."""
    out = _save_auto_topup(check=True)
    assert len(out["posts"]) == 1
    (_m, path, body), = out["posts"]
    assert path == "api/customer/billing/auto-topup"
    assert body == {"enabled": True, "trigger_credits": 25, "pack_price_id": "price_topup_big",
                    "monthly_cap_credits": 2000}
    assert body["enabled"] is True                                           # a REAL boolean, not a truthy value
    assert "org_id" not in body and "amount" not in body and "amount_minor" not in body   # tenant + money are server's


def test_saving_auto_topup_off_sends_a_strict_boolean_false():
    """An unchecked box turns it off with a strict boolean ``False`` — never a falsy-but-not-False value, and never
    silently left on."""
    out = _save_auto_topup(check=False)
    (_m, _path, body), = out["posts"]
    assert body["enabled"] is False


def test_auto_topup_is_an_honest_note_when_the_feature_is_off_or_refused():
    """With the feature off the read is a 404 (and a non-billing role a 403): the control opens to an honest note, not
    a form and not a crash, and its button is usable again."""
    out = _node(_wiring_fns("1"), r"""
const calls = [];
VUI.getJSON = async (p) => { calls.push(p); const e = new Error('off'); e.status = 404; throw e; };
const sec = autoTopupSection(); document.body.appendChild(sec);
const open = sec.querySelectorAll('button').filter(b => b.textContent === 'Set up auto top-up')[0];
open.click(); await tick(); await tick();
out.text = sec.textContent; out.calls = calls;
out.saveButtons = sec.querySelectorAll('button').filter(b => b.textContent === 'Save auto top-up').length;
out.openDisabled = open.disabled === true;
""", is_async=True)
    assert out["calls"] == ["api/customer/billing/auto-topup"]
    assert "not available on your account right now" in out["text"]
    assert out["saveButtons"] == 0                                           # no form rendered
    assert out["openDisabled"] is False                                     # the control is usable again


def test_the_low_balance_notice_only_shows_when_flagged():
    """The notice follows the SERVER's low-balance flag (W5) and nothing else: present only while it is set."""
    out = _node(_render_fns(), r"""
out.flagged = lowBalanceNotice(""" + json.dumps(_OV) + r""").textContent;
var calm = Object.assign({}, """ + json.dumps(_OV) + r"""); delete calm.low_balance;
out.absent = lowBalanceNotice(calm) === null;
out.cleared = lowBalanceNotice(Object.assign({}, calm, { low_balance: false })) === null;
""")
    assert "Your balance is low." in out["flagged"] and "Add credits" in out["flagged"]
    assert out["absent"] is True and out["cleared"] is True                  # not flagged -> no notice at all


def test_the_guide_names_the_dashboards_real_labels():
    """guide.js's Billing steps describe this screen in words; every control they name exists here with that label,
    so the guide (still OFF until all of §15.11 C is in) and the screen stay in step."""
    steps = {(ch["id"], st["id"]): st for ch in _guide()["chapters"] for st in ch["steps"]}
    src = _js()
    dash = "\n".join(_fn(src, n) for n in ("viewBillingDashboard", "billingCreditsCard", "billingUsageCard",
                                            "runningScansCard", "statementCard", "ratesSection", "autoTopupSection"))
    for key, words, label in (
            (("credits", "buy"), "Your available credits are at the top", 'kv("Available", mc2(ov.exact_available_mc))'),
            (("credits", "rates"), "select Rates", 'text: "Rates" }'),
            (("credits", "alerts"), "turn on Auto top-up", 'VUI.card("Auto top-up"'),
            (("billing", "statement"), "what is on hold for running assessments", '"On hold for running assessments"'),
            (("billing", "statement"), "what you bought", 'kv("Credits bought"'),
            (("billing", "statement"), "what you used", 'kv("Credits used"'),
            (("billing", "statement"), "Each running assessment shows what it has used so far",
             'VUI.card("Running assessments"'),
            (("billing", "statement"), "Your statement lists every charge, newest first", 'VUI.card("Statement"')):
        assert steps[key]["route"] == "#/billing", key
        assert any(words in c for c in steps[key]["clicks"]), (key, words)       # the guide says it ...
        assert label in dash, (key, label)                                       # ... and the screen has it
