"""SIGIL — provider TOKEN + COST metering on the daily budget (SIGIL §5). These prove the metering
seam that budget.py's docstring called out is now closed WITHOUT a separate counter:

  * token/cost spend is DERIVED FROM THE SPINE (payload["usage"]), the same way actions are derived;
  * token and cost caps enforce FAIL-CLOSED (at/over cap → deny), matching action/interrupt semantics;
  * opt-in: None caps ⇒ unthrottled AND, with no usage supplied, the record is byte-identical;
  * a DENIED action consumes NO budget (its refusal record carries no usage);
  * cost is FROZEN at record time — editing the price table never rewrites historical spend;
  * report() is a read-only per-agent view and counts only actions actually TAKEN.

Run: SIGIL_HOME=$(mktemp -d) ~/.sigil/venv/bin/pytest tests/test_budget_metering.py -q"""
import tempfile
from datetime import datetime, timezone

from sigil.agents.base import Agent, Proposal, Tier
from sigil.governor import BudgetCaps, Governor, Spend, Usage, load_prices
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _gov(store, *, caps=None):
    return Governor(store, caps=caps, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _today():
    return datetime.now(timezone.utc).date().isoformat()


class _Emitter(Agent):
    """A minimal agent that dispatches one proposal (optionally carrying provider usage)."""
    ceiling = Tier.A2

    def __init__(self, store, name="TESTER", *, caps=None):
        super().__init__(store, governor=_gov(store, caps=caps))
        self.name = name

    def emit(self, tier=Tier.A1, *, kind="event", usage=None):
        return self._dispatch([Proposal(kind, {"subject": "x"}, tier, usage=usage)])


# ---- token/cost spend derives from the spine ------------------------------------------------------
def test_token_and_cost_spend_derives_from_the_spine():
    s = _store()
    led = _gov(s).budget
    t = _Emitter(s)
    t.emit(usage=Usage(input_tokens=100, output_tokens=40, model="x", cost_usd=0.5))
    t.emit(usage=Usage(input_tokens=10, output_tokens=0, model="x", cost_usd=0.25))
    sp = led.spent("TESTER", _today())
    assert isinstance(sp, Spend)
    assert sp.actions == 2
    assert sp.tokens == 150            # (100+40) + (10+0)
    assert abs(sp.cost_usd - 0.75) < 1e-9
    # nothing stamped when no usage is supplied → no tokens/cost, still a real action
    t.emit()
    sp2 = led.spent("TESTER", _today())
    assert sp2.actions == 3 and sp2.tokens == 150 and abs(sp2.cost_usd - 0.75) < 1e-9


def test_cost_derives_from_the_price_table_when_not_explicit():
    # 1M input + 1M output on claude-haiku-4-5 ($1 in / $5 out per MTok) → $6.00, computed from the
    # default table (no explicit cost_usd), so the datum on the spine already carries the frozen cost.
    s = _store()
    _Emitter(s).emit(usage=Usage(input_tokens=1_000_000, output_tokens=1_000_000, model="claude-haiku-4-5"))
    sp = _gov(s).budget.spent("TESTER", _today())
    assert sp.tokens == 2_000_000
    assert abs(sp.cost_usd - 6.0) < 1e-9


def test_unpriced_model_meters_tokens_but_zero_cost():
    s = _store()
    _Emitter(s).emit(usage=Usage(input_tokens=500, output_tokens=500, model="mystery-model-9000"))
    sp = _gov(s).budget.spent("TESTER", _today())
    assert sp.tokens == 1000 and sp.cost_usd == 0.0


# ---- caps enforce FAIL-CLOSED (at/over cap → deny) ------------------------------------------------
def test_token_cap_denies_fail_closed():
    s = _store()
    t = _Emitter(s, caps=BudgetCaps(daily_tokens=100))
    assert t.emit(usage=Usage(input_tokens=60, output_tokens=0, model="local")).applied  # 60  < 100
    assert t.emit(usage=Usage(input_tokens=60, output_tokens=0, model="local")).applied  # 120 written
    r = t.emit(usage=Usage(input_tokens=60, output_tokens=0, model="local"))             # 120 >= 100
    assert not r.applied and any("token cap" in n for n in r.notes)


def test_cost_cap_denies_fail_closed():
    s = _store()
    t = _Emitter(s, caps=BudgetCaps(daily_cost_usd=1.0))
    assert t.emit(usage=Usage(model="x", cost_usd=0.6)).applied   # 0.6  < 1.0
    assert t.emit(usage=Usage(model="x", cost_usd=0.6)).applied   # 1.2 recorded
    r = t.emit(usage=Usage(model="x", cost_usd=0.6))              # 1.2 >= 1.0
    assert not r.applied and any("cost cap" in n for n in r.notes)


def test_denied_action_consumes_no_budget():
    s = _store()
    led = _gov(s).budget
    t = _Emitter(s, caps=BudgetCaps(daily_tokens=100))
    t.emit(usage=Usage(input_tokens=60, model="local"))
    t.emit(usage=Usage(input_tokens=60, model="local"))          # now at 120, over cap
    before = led.spent("TESTER", _today())
    r = t.emit(usage=Usage(input_tokens=999, model="local"))     # DENIED — must not meter its 999
    assert not r.applied
    after = led.spent("TESTER", _today())
    assert after.tokens == before.tokens == 120, "a denied action's usage never advances the meter"


# ---- opt-in: None caps ⇒ unchanged default -------------------------------------------------------
def test_uncapped_token_cost_is_unthrottled_and_opt_in():
    s = _store()
    t = _Emitter(s)                       # no caps at all
    for _ in range(6):
        assert t.emit(usage=Usage(input_tokens=10_000, model="claude-opus-4-8")).applied
    sp = _gov(s).budget.spent("TESTER", _today())
    assert sp.actions == 6 and sp.tokens == 60_000


def test_no_usage_record_is_byte_identical_to_pre_metering_path():
    s = _store()
    res = _Emitter(s).emit()              # no usage supplied
    seq = res.applied[0]
    rec = next(r for r in s.iter_records() if r.seq == seq)
    assert "usage" not in rec.payload, "no usage supplied ⇒ no metering key stamped (unchanged record)"


# ---- cost is FROZEN at record time (price table edits don't rewrite history) ---------------------
def test_recorded_cost_is_frozen_against_later_price_changes(monkeypatch):
    s = _store()
    # record at the default haiku price: 1M input × $1/MTok = $1.00
    _Emitter(s).emit(usage=Usage(input_tokens=1_000_000, output_tokens=0, model="claude-haiku-4-5"))
    led = _gov(s).budget
    assert abs(led.spent("TESTER", _today()).cost_usd - 1.0) < 1e-9
    # now 10x the price via env override — the ACTIVE table changes...
    monkeypatch.setenv("SIGIL_MODEL_PRICES", '{"claude-haiku-4-5": [10.0, 50.0]}')
    assert load_prices()["claude-haiku-4-5"] == (10.0, 50.0)
    # ...but the already-recorded spend is unchanged: cost was frozen into the record, not re-derived.
    assert abs(led.spent("TESTER", _today()).cost_usd - 1.0) < 1e-9


# ---- report(): read-only per-agent view; denials excluded ----------------------------------------
def test_report_aggregates_per_agent_and_excludes_denials():
    s = _store()
    scout = _Emitter(s, "SCOUT")
    scout.emit(kind="finding", usage=Usage(input_tokens=200, output_tokens=100, model="x", cost_usd=0.3))
    scout.emit(kind="event", usage=Usage(input_tokens=50, output_tokens=0, model="x", cost_usd=0.1))
    envoy = _Emitter(s, "ENVOY", caps=BudgetCaps(daily_tokens=0))  # 0-token budget: every action denied
    r = envoy.emit(usage=Usage(input_tokens=999, model="x", cost_usd=9.0))  # DENIED at cap → not reported
    assert not r.applied

    rep = _gov(s).budget.report(_today())
    assert set(rep) == {"SCOUT"}, "denied-only agents contribute nothing to the report"
    sc = rep["SCOUT"]
    assert sc == {"actions": 2, "interrupts": 1, "tokens": 350, "cost_usd": 0.4}


# ---- malformed usage on the spine can't crash the enforcement path -------------------------------
def test_malformed_usage_is_ignored_not_fatal():
    s = _store()
    # a hand-written / forged record with junk usage values — must coerce to 0, never raise.
    s.append(kind="event", source="agent", actor="TESTER",
             payload={"decision": "auto", "usage": {"input_tokens": "NaN", "output_tokens": None,
                                                     "cost_usd": "x"}})
    sp = _gov(s).budget.spent("TESTER", _today())
    assert sp.actions == 1 and sp.tokens == 0 and sp.cost_usd == 0.0
    # a usage that isn't even a dict is ignored wholesale
    s.append(kind="event", source="agent", actor="TESTER", payload={"decision": "auto", "usage": "junk"})
    sp2 = _gov(s).budget.spent("TESTER", _today())
    assert sp2.actions == 2 and sp2.tokens == 0 and sp2.cost_usd == 0.0


# ---- review BLOCK-1: a NEGATIVE usage datum must not cancel real spend (fail-open cap bypass) -----
def test_negative_usage_cannot_cancel_spend():
    s = _store()
    led = _gov(s).budget
    s.append(kind="tool_call", source="agent", actor="TESTER",     # a real 900-token / $0.90 action
             payload={"decision": "auto", "usage": {"input_tokens": 900, "output_tokens": 0, "cost_usd": 0.90}})
    s.append(kind="tool_call", source="agent", actor="TESTER",     # a FORGED record trying to cancel it
             payload={"decision": "auto", "usage": {"input_tokens": -900, "output_tokens": -50, "cost_usd": -0.90}})
    sp = led.spent("TESTER", _today())
    assert sp.tokens >= 900, f"negative tokens must not cancel real spend (got {sp.tokens})"
    assert sp.cost_usd >= 0.90 - 1e-9, f"negative cost must not cancel real spend (got {sp.cost_usd})"


# ---- review BLOCK-2: a forged huge-INTEGER cost must not crash the gate (DoS) ---------------------
def test_huge_int_cost_does_not_crash_the_gate():
    s = _store()
    led = _gov(s, caps=BudgetCaps(daily_cost_usd=1.0)).budget
    huge = int("9" * 401)                                          # a valid JSON int; float(huge) -> OverflowError
    s.append(kind="tool_call", source="agent", actor="VICTIM",
             payload={"decision": "auto", "usage": {"input_tokens": 1, "output_tokens": 0, "cost_usd": huge}})
    assert led.spent("VICTIM", _today()).cost_usd == 0.0           # un-representable cost coerces to 0, no raise
    assert led.over_budget("VICTIM", _today())[0] in (True, False) # returns a verdict, does not crash the dispatch
    led.report(_today())                                          # the `sigil budget` path must not crash either
