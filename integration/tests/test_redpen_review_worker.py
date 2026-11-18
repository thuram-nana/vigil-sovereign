"""R3 — the Red-Pen PR-review worker posts ONLY reproduced FACTs, never a LEAD, and honors the reserve refusal.

Framework-free (fake GitHub, fake reserve/settle/emit, a crafted ``RedPenReport``): the worker's CONTRACT is to
consume a report, post each FACT (severity-marked, with the reproduce command + evidence ref + the Fix-this
marker) via the gated comment executor, never post a LEAD (decision O-1), settle the charge, and emit an inert
outcome carrying only FACT severities. The reproduction engine + the real oracle gate are proven in R1's suite;
the end-to-end real-engine path is ``test_redpen_review_worker_e2e.py`` (framework leg).
"""
from __future__ import annotations

import re
import types

import pytest

from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.redpen_review import (
    _FIX_THIS_MARKER, build_review_outcome, fix_this_marker, make_redpen_review_worker, parse_fix_this_marker,
    reproduce_command,
)
from vigil_integration.redpen import RedPenFact, RedPenLead, RedPenReport

SLUG, ORG, REPO, HEAD = "cust_abc123", "org_a", "github.com/acme/widgets", "c0ffee1234"


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    """The master flag ON for the contract tests; the flag-off tests below turn it off explicitly."""
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


def _job():
    return SecurityJob(source="webhook", repo=REPO, commit=HEAD, pr_number=7, profile="redpen",
                       delivery_id="work-xyz")


def _report(*, facts=(), leads=()):
    return RedPenReport(enabled=True, facts=tuple(facts), leads=tuple(leads))


def _fact(bug="sql_injection", sev="high", ref="sqli~L10", confirmed="sql_injection_breakout"):
    return RedPenFact(bug_class=bug, confirmed_by=confirmed, severity=sev, finding_ref=ref,
                      reason="reproduced + oracle-confirmed", lens="injection", file="app/db.py", line=10,
                      confidence=0.99, signed=object())


def _lead(bug="xss", sev="medium", ref="xss~L20"):
    return RedPenLead(bug_class=bug, severity=sev, finding_ref=ref, reason="not reproduced twice",
                      lens="client_side", file="web/x.js", line=20, outcome="no_fire")


class _Recorder:
    def __init__(self):
        self.posts = []
        self.emitted = []
        self.records = []
        self.settled = []
        self.checkouts = 0
        self.ran = 0

    def post(self, **kw):
        self.posts.append(kw)
        n = len(self.posts)
        return {"id": 1000 + n, "html_url": f"https://example/comment/{1000 + n}"}

    def emit(self, env):
        self.emitted.append(env)

    def record(self, env):
        self.records.append(env)

    def settle(self, res, report):
        self.settled.append((res, report))


def _ok_reserve(job):
    return {"ok": True, "slug": SLUG, "org_id": ORG, "nonce": "n1", "units_reserved": 3}


def _build(rec, *, report, comment_enabled=True, reserve=_ok_reserve, changed=None):
    changed = {"app/db.py"} if changed is None else changed

    def checkout(_job):
        rec.checkouts += 1
        return "/tmp/checkout"

    def changed_files(_job):
        return changed

    def run_review(**kw):
        rec.ran += 1
        rec._run_kw = kw
        return report

    return make_redpen_review_worker(
        reserve=reserve, checkout=checkout, changed_files=changed_files,
        comment_config=types.SimpleNamespace(comment_enabled=comment_enabled),
        trust_root=object(), approve=lambda *a, **k: True, audit=lambda rec_: None, signers=[("g", "k")],
        settle=rec.settle, emit_outcome=rec.emit, record_review=rec.record, _run_review=run_review, _post=rec.post)


# ---- FACT posted; LEAD never posted -----------------------------------------------------------------

def test_a_reproduced_fact_is_posted_with_reproduce_cmd_evidence_and_fix_this_marker():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()], leads=[_lead()]))
    out = worker(_job())
    assert out["review"] == "ran" and len(rec.posts) == 1          # exactly the one FACT
    body = rec.posts[0]["body"]
    assert "🔴" in body and "High" in body and "blocks merge" in body   # severity marker + blocking copy
    assert reproduce_command(SLUG, "sqli~L10") in body                # the reproduce command verbatim
    assert "sqli~L10" in body                                         # the evidence ref
    assert _FIX_THIS_MARKER.format(ref="sqli~L10") in body            # the machine Fix-this marker R5 keys on
    assert rec.posts[0]["repo"] == REPO and rec.posts[0]["pr_number"] == 7 and rec.posts[0]["slug"] == SLUG


def test_a_lead_is_never_posted_even_when_no_fact_exists():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[], leads=[_lead(), _lead(bug="idor", ref="idor~L5")]))
    out = worker(_job())
    assert rec.posts == []                                           # LEADs are dashboard-only (O-1)
    assert out["review"] == "ran" and out["lead_count"] == 2 and out["facts_seen"] == 0


def test_only_the_facts_are_posted_when_facts_and_leads_coexist():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact(), _fact(bug="cmdi", ref="cmdi~L3",
                                                              confirmed="command_injection_breakout")],
                                        leads=[_lead(), _lead(bug="ssrf", ref="ssrf~L9")]))
    worker(_job())
    posted_refs = sorted(p["body"].split("ref: `")[1].split("`")[0] for p in rec.posts)
    assert len(rec.posts) == 2 and posted_refs == ["cmdi~L3", "sqli~L10"]   # the two FACTs, neither LEAD


def test_the_medium_and_low_markers_are_non_blocking():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact(sev="medium", ref="m~L1"),
                                               _fact(sev="low", ref="l~L2")]))
    worker(_job())
    bodies = {p["body"].split("ref: `")[1].split("`")[0]: p["body"] for p in rec.posts}
    assert "🟠" in bodies["m~L1"] and "blocks merge" not in bodies["m~L1"]
    assert "🟡" in bodies["l~L2"] and "blocks merge" not in bodies["l~L2"]


# ---- the reserve refusal (monthly limit / off-flag / unconnected) runs NO review --------------------

def test_a_reserve_refusal_runs_no_review_posts_nothing_and_emits_a_non_blocking_outcome():
    rec = _Recorder()

    def refusing_reserve(job):
        return {"ok": False, "slug": SLUG, "org_id": ORG,
                "error": "this repository has reached its monthly review spending limit"}

    worker = _build(rec, report=_report(facts=[_fact()]), reserve=refusing_reserve)
    out = worker(_job())
    assert out["review"] == "refused" and "monthly" in out["reason"]
    assert rec.posts == [] and rec.ran == 0 and rec.checkouts == 0   # the review never ran; nothing posted
    assert len(rec.emitted) == 1
    env = rec.emitted[0]
    assert env["refused"] is True and env["fact_severities"] == [] and env["facts"] == []   # non-blocking outcome
    (record,) = rec.records                                          # the dashboard learns WHY it did not run
    assert record["refused"] is True and "monthly" in record["reason"]
    assert record["facts"] == [] and record["leads"] == []


# ---- the inert outcome carries only FACT severities, never a LEAD -----------------------------------

def test_the_outcome_envelope_carries_only_fact_severities_never_leads():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact(sev="critical", ref="c~L1")],
                                        leads=[_lead(sev="critical", ref="lead~L2")]))
    worker(_job())
    env = rec.emitted[0]
    assert env["schema"] == "vigil.redpen.review-outcome.v1"
    assert env["fact_severities"] == ["critical"]                   # the FACT's severity
    assert env["lead_count"] == 1 and "lead~L2" not in str(env["facts"])   # the LEAD never crosses
    assert env["org_id"] == ORG and env["repo"] == REPO and env["head_sha"] == HEAD


def test_build_review_outcome_drops_lead_rows_entirely():
    env = build_review_outcome(_job(), _report(facts=[_fact(sev="high")], leads=[_lead(), _lead()]), slug=SLUG,
                               org_id=ORG)
    assert env["fact_severities"] == ["high"] and env["lead_count"] == 2
    assert all(row["severity"] == "high" for row in env["facts"]) and len(env["facts"]) == 1


# ---- the comment gate + fail-closed scope + record-don't-abort --------------------------------------

def test_comment_disabled_posts_nothing_but_still_reviews_and_emits():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()]), comment_enabled=False)
    out = worker(_job())
    assert rec.posts == [] and out["review"] == "ran" and len(rec.emitted) == 1   # no owner opt-in ⇒ no post


def test_empty_changed_files_fails_closed_rather_than_a_silent_clean():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()]), changed=set())   # empty scope
    with pytest.raises(ValueError):
        worker(_job())
    assert rec.ran == 0                                              # never reviewed an undetermined scope


def test_a_post_failure_is_recorded_not_fatal():
    rec = _Recorder()

    def boom_post(**kw):
        raise RuntimeError("github 500")

    worker = make_redpen_review_worker(
        reserve=_ok_reserve, checkout=lambda j: "/tmp/c", changed_files=lambda j: {"a.py"},
        comment_config=types.SimpleNamespace(comment_enabled=True), trust_root=object(),
        approve=lambda *a, **k: True, audit=lambda r: None, signers=[("g", "k")], emit_outcome=rec.emit,
        _run_review=lambda **kw: _report(facts=[_fact(), _fact(bug="cmdi", ref="cmdi~L3")]), _post=boom_post)
    out = worker(_job())
    assert len(out["facts_refused"]) == 2 and out["facts_posted"] == []   # both recorded, review not aborted
    assert len(rec.emitted) == 1                                     # the outcome still emitted


def test_the_charge_is_settled_after_a_review():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()]))
    worker(_job())
    assert len(rec.settled) == 1 and rec.settled[0][0]["slug"] == SLUG   # settle(reservation, report) once


def test_reproduce_command_is_customer_safe_no_engine_name():
    cmd = reproduce_command(SLUG, "sqli~L10")
    low = cmd.lower()
    assert "vigil" in low and "sqli~L10" in cmd
    for forbidden in ("claude", "anthropic", "opus", "sonnet", "haiku", "strix", "nyx", "llm", "gpt"):
        assert forbidden not in low


def test_a_hostile_ref_cannot_break_out_of_the_fix_this_marker():
    # finding_ref / bug_class can be model-proposed from the reviewed diff: a ref spelling "-->" must never close
    # the HTML comment early and smuggle markdown into the posted body.
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact(ref="x --> <img src=y> <!-- z")]))
    worker(_job())
    body = rec.posts[0]["body"]
    marker_line = [ln for ln in body.splitlines() if ln.startswith("<!-- VIGIL-RED-PEN:FIX-THIS")]
    assert len(marker_line) == 1 and marker_line[0].count("-->") == 1 and marker_line[0].endswith(" -->")
    assert "<img" not in marker_line[0] and "<!-- z" not in marker_line[0]


# ---- flag OFF: the worker and both CLI drains are byte-identically absent ------------------------------

def test_with_red_pen_off_the_worker_is_inert_before_any_side_effect(monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED")
    rec = _Recorder()
    reserved = []

    def reserve(job):
        reserved.append(job)
        return _ok_reserve(job)

    worker = _build(rec, report=_report(facts=[_fact()]), reserve=reserve)
    out = worker(_job())
    assert out["review"] == "disabled"
    # no reserve, no clone, no GitHub read, no review, no post, no settle, no emit
    assert reserved == [] and rec.checkouts == 0 and rec.ran == 0
    assert rec.posts == [] and rec.settled == [] and rec.emitted == [] and rec.records == []


@pytest.mark.parametrize("argv", [
    ["redpen-review", "--queue-root", "Q", "--github-token", "t"],
    ["redpen-webhook-drain", "--spool", "S", "--queue-root", "Q"],
])
def test_with_red_pen_off_both_cli_drains_refuse_and_touch_nothing(monkeypatch, tmp_path, argv):
    from vigil_integration import cli as climod
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED")
    monkeypatch.chdir(tmp_path)
    args = climod.build_parser().parse_args(argv)
    assert args.func(args) == 2
    assert list(tmp_path.iterdir()) == []                          # no spool, no queue, nothing created


# ---- the dashboard record: LEADs live here (and only here); FACTs pair with their posted comment ---------

_FORBIDDEN = re.compile(r"(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)", re.I)


def test_the_review_record_keeps_every_lead_for_the_dashboard_without_internal_text():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()], leads=[_lead(), _lead(bug="idor", ref="idor~L5")]))
    out = worker(_job())
    (record,) = rec.records
    assert record["schema"] == "vigil.redpen.review-record.v1" and record["refused"] is False
    assert [x["finding_ref"] for x in record["leads"]] == ["xss~L20", "idor~L5"]      # every LEAD, retained
    assert record["leads"][0] == {"bug_class": "xss", "severity": "medium", "finding_ref": "xss~L20",
                                  "file": "web/x.js", "line": 20, "outcome": "no_fire"}
    blob = repr(record)
    assert "not reproduced twice" not in blob and "client_side" not in blob   # no engine reason, no lens id
    assert out["record"] == record and record["org_id"] == ORG and record["head_sha"] == HEAD


def test_each_fact_row_pairs_with_its_posted_comment_and_the_fix_ref_its_marker_carries():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact(ref="sqli~L10"),
                                               _fact(bug="cmdi", ref="cmdi~L3", confirmed="command_injection_breakout")]))
    worker(_job())
    (record,) = rec.records
    by_ref = {row["finding_ref"]: row for row in record["facts"]}
    for post in rec.posts:
        fix_ref = parse_fix_this_marker(post["body"])
        row = next(r for r in record["facts"] if r["fix_ref"] == fix_ref)
        assert row["comment"] is not None and row["comment"]["id"] >= 1001
    assert by_ref["sqli~L10"]["comment"]["id"] != by_ref["cmdi~L3"]["comment"]["id"]   # paired by position
    assert by_ref["sqli~L10"]["reproduce"] == reproduce_command(SLUG, "sqli~L10")


def test_with_comments_off_the_record_still_lists_the_facts_with_no_comment():
    rec = _Recorder()
    worker = _build(rec, report=_report(facts=[_fact()]), comment_enabled=False)
    worker(_job())
    (record,) = rec.records
    assert len(record["facts"]) == 1 and record["facts"][0]["comment"] is None


def test_the_comment_never_prints_an_internal_lens_identifier():
    # a FACT found by the prompt-injection lens: the customer-facing comment shows the bug class, never the lens id
    rec = _Recorder()
    fact = RedPenFact(bug_class="prompt_injection", confirmed_by="side_effect", severity="high",
                      finding_ref="pi~L7", reason="r", lens="llm_prompt_injection", file="bot/agent.py", line=7)
    worker = _build(rec, report=_report(facts=[fact]))
    worker(_job())
    body = rec.posts[0]["body"]
    assert "llm_prompt_injection" not in body and not _FORBIDDEN.search(body), body


def test_parse_fix_this_marker_reads_only_the_trailing_marker():
    # a marker-shaped string quoted earlier in the body (e.g. inside a model-proposed bug class) is a decoy: only
    # the LAST line — the one the worker writes — counts, and it carries the sanitised ref.
    body = "\n".join(["**x**", "- bug: " + fix_this_marker("decoy~1"), "", fix_this_marker("real ref/x")])
    assert parse_fix_this_marker(body) == "real-ref/x"
    assert parse_fix_this_marker("no marker here") is None and parse_fix_this_marker("") is None
    assert parse_fix_this_marker(body + "\ntrailing text") is None    # a marker that is not last is not ours
