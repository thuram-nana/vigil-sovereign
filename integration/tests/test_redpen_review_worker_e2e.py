"""R3 — end to end through the REAL reproduction engine: spool → Red-Pen drain → queue → JobRunner → worker → FACT.

The unit suite (``test_redpen_review_worker.py``) pins the worker's contract over a crafted report; this drives the
whole offense path with the REAL pieces — the Red-Pen webhook drain, the real ``SecurityJobQueue``, the SOLE
executor ``JobRunner.run_one`` (via ``make_redpen_review_runner``), the real ``run_redpen`` engine and the real
``confirm_and_certify`` oracle firewall with a real governance signer — faking only the S5 sandbox (no bwrap, no
network) and the GitHub comment POST (captured). Pins:
  * a candidate reproduced TWICE and confirmed by the offline oracle becomes a posted, severity-marked FACT with the
    reproduce command + evidence ref + the Fix-this marker, and the emitted outcome carries its severity;
  * a CRITICAL candidate that fires only ONCE is a LEAD: never posted, never a severity in the outcome;
  * a job the authorization gate refuses never reaches the worker (no review, no post, no outcome).

Needs framework (the real oracle + the real queue) → runs in the OFFENSE CI leg; skips in the sovereign leg.
"""
from __future__ import annotations

import functools
import hashlib
import json
import types
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify.poc_translate")

from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.jobs.authorize import GateOutcome  # noqa: E402
from vigil_integration.jobs.queue import SecurityJobQueue  # noqa: E402
from vigil_integration.jobs.redpen_review import (  # noqa: E402
    _FIX_THIS_MARKER, make_redpen_review_runner, make_redpen_review_worker, parse_fix_this_marker,
    reproduce_command,
)
from vigil_integration.live.sandbox_exec import SandboxOutcome  # noqa: E402
from vigil_integration.redpen import LensCandidate, LensResponse, run_redpen  # noqa: E402
from vigil_integration.redpen_webhook_drain import RedpenWebhookDrain  # noqa: E402

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]
SLUG = "cust_e2e"

_SQLI = LensCandidate(
    lens="injection", bug_class="sqli_attempt", channel="request_payload", poc_command="python poc.py",
    fire_markers=("SINK_REACHED",), request_value="' OR '1'='1", param="q", severity="high",
    finding_ref="rp-sqli-1", file="app/db.py", line=12)
# CRITICAL, but it fires only ONCE in the sandbox — a flake, so it must stay a LEAD and never be posted.
_FLAKY = LensCandidate(
    lens="ssrf_egress", bug_class="ssrf_attempt", channel="request_payload", poc_command="python flaky.py",
    fire_markers=("SINK_REACHED",), request_value="http://169.254.169.254/latest/meta-data/", param="url",
    severity="critical", finding_ref="rp-flaky-1", file="app/fetch.py", line=4)


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


def _sandbox():
    runs: dict = {}

    def sandbox(cmd):
        runs[cmd] = runs.get(cmd, 0) + 1
        if cmd == "python flaky.py" and runs[cmd] > 1:
            return SandboxOutcome(exit_code=0, stdout="no effect", stderr="")    # the second run does not fire
        return SandboxOutcome(exit_code=0, stdout="SINK_REACHED at db.execute", stderr="")
    return sandbox


def _reviewer(req):
    by_lens = {"injection": (_SQLI,), "ssrf_egress": (_FLAKY,)}
    return LensResponse(candidates=by_lens.get(req.lens, ()))


def _spool_pr(spool: Path, *, delivery: str, commit: str) -> None:
    env = {"schema": "vigil.webhook.github.redpen.v1", "delivery_id": delivery, "event": "pull_request",
           "action": "opened", "kind": "pr", "repo": "github.com/acme/widget", "commit": commit, "pr_number": 7}
    inc = spool / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    data = json.dumps(env, sort_keys=True).encode()
    (inc / (hashlib.sha256(data).hexdigest()[:32] + ".json")).write_bytes(data)


def _runner(tmp_path: Path, q, *, gate, posts: list, emitted: list, records: "list | None" = None):
    worker = make_redpen_review_worker(
        reserve=lambda job: {"ok": True, "slug": SLUG, "org_id": "org_a", "nonce": "n", "units_reserved": 2},
        checkout=lambda job: str(tmp_path / "checkout"), changed_files=lambda job: {"app/db.py", "app/fetch.py"},
        comment_config=types.SimpleNamespace(comment_enabled=True), trust_root=None,
        approve=lambda *a, **k: True, audit=lambda r: None, signers=SIGNERS, reviewer=_reviewer,
        emit_outcome=emitted.append, record_review=(records if records is not None else []).append,
        lenses=("injection", "ssrf_egress"),
        _run_review=functools.partial(run_redpen, sandbox=_sandbox()),
        _post=lambda **kw: posts.append(kw) or {"id": 900 + len(posts), "html_url": "https://example/c"})
    return make_redpen_review_runner(
        queue_root=str(tmp_path / "queue"), trust_root=None, reserve=lambda j: {}, checkout=lambda j: "",
        changed_files=lambda j: set(), comment_config=None, approve=None, audit=None, signers=SIGNERS,
        _queue=q, _gate=gate, _worker=worker)


def test_a_reproduced_fact_is_posted_end_to_end_and_a_one_shot_critical_lead_never_is(tmp_path):
    (tmp_path / "checkout").mkdir()
    q = SecurityJobQueue(tmp_path / "queue")
    spool = tmp_path / "spool" / "redpen"
    _spool_pr(spool, delivery="D-1", commit="c0ffee1234")
    assert RedpenWebhookDrain(spool_dir=spool, queue=q).drain()["enqueued"] == 1

    posts: list = []
    emitted: list = []
    records: list = []
    outcomes = _runner(tmp_path, q, gate=lambda job: GateOutcome(True, "ok"), posts=posts,
                       emitted=emitted, records=records).drain()
    assert [o.state for o in outcomes] == ["done"]
    result = outcomes[0].result
    assert result["review"] == "ran" and result["facts_seen"] == 1 and result["lead_count"] == 1

    assert len(posts) == 1                                         # ONLY the reproduced FACT is posted
    body = posts[0]["body"]
    assert "🔴" in body and "High" in body and "blocks merge" in body
    assert reproduce_command(SLUG, "rp-sqli-1") in body and "rp-sqli-1" in body
    assert _FIX_THIS_MARKER.format(ref="rp-sqli-1") in body
    assert "rp-flaky-1" not in body and "ssrf" not in body.lower()   # the one-shot critical LEAD never posted
    assert posts[0]["repo"] == "github.com/acme/widget" and posts[0]["pr_number"] == 7

    (env,) = emitted
    assert env["fact_severities"] == ["high"]                      # the LEAD's "critical" never crosses
    assert env["lead_count"] == 1 and env["head_sha"] == "c0ffee1234" and env["org_id"] == "org_a"

    (record,) = records                                            # ...but the dashboard keeps it
    assert [x["finding_ref"] for x in record["leads"]] == ["rp-flaky-1"] and record["leads"][0]["severity"] == \
        "critical"
    (fact_row,) = record["facts"]
    assert fact_row["finding_ref"] == "rp-sqli-1" and fact_row["comment"]["id"] == 901
    assert parse_fix_this_marker(body) == fact_row["fix_ref"]      # the posted marker ↔ the dashboard row


def test_a_job_the_gate_refuses_never_reaches_the_worker(tmp_path):
    (tmp_path / "checkout").mkdir()
    q = SecurityJobQueue(tmp_path / "queue")
    spool = tmp_path / "spool" / "redpen"
    _spool_pr(spool, delivery="D-2", commit="beef5678")
    assert RedpenWebhookDrain(spool_dir=spool, queue=q).drain()["enqueued"] == 1

    posts: list = []
    emitted: list = []
    outcomes = _runner(tmp_path, q, gate=lambda job: GateOutcome(False, "no authority", "unverified_authority"),
                       posts=posts, emitted=emitted).drain()
    assert [o.state for o in outcomes] == ["refused"]
    assert posts == [] and emitted == []                           # no review ran, nothing posted or emitted
