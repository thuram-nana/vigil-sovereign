"""R3 — the "VIGIL Red-Pen" check run, written SOVEREIGN-side from an inert review outcome (decision O-5).

Invariants pinned here:
  * the conclusion is decided ONLY by reproduced-FACT severities under the repository's owner-signed threshold —
    ``failure`` iff a FACT is at/above it (CRITICAL_HIGH blocks Critical/High, MEDIUM_UP blocks Medium and up, NONE
    never blocks); below-threshold FACTs and a refused review are ``neutral``; a clean review is ``success``;
  * a LEAD can never block (a LEAD never appears in ``fact_severities``; any other field is ignored);
  * an unknown threshold falls to the STRICTEST default — never fail-open to "never block";
  * the threshold + installation come ONLY from the owner-signed connected-repo record (no caller override): an
    unconnected repo, another org's record, or a malformed outcome refuses BEFORE any token is minted;
  * behind VIGIL_REDPEN_ENABLED: off ⇒ the write refuses even with injected seams, and the drain touches nothing;
  * end-to-end against a FAKE GitHub: the App JWT mints an installation token for the RECORD's installation, which
    writes the "VIGIL Red-Pen" check (conclusion failure) at the head sha;
  * the producer (offense ``build_review_outcome`` + spooler) and this consumer agree on the envelope (contract);
  * the outcome drain archives a written check, quarantines a definitive refusal, retries an egress failure a
    bounded number of times, and reclaims a crashed claim;
  * customer-facing check copy names no engine / model and quotes no amount.
NO network — a fake GitHub is injected through the egress transport seam.
"""
from __future__ import annotations

import itertools
import json
import re
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sigil.governor import redpen_check as rc
from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from vigil_core import BlockThreshold
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.redpen_review import build_review_outcome, make_inert_spooler
from vigil_integration.redpen import RedPenFact, RedPenLead, RedPenReport

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_c = itertools.count(1)
ORG, REPO, HEAD = "org_a", "github.com/acme/widgets", "ab" * 20


@pytest.fixture(autouse=True)
def _flag_on(monkeypatch):
    monkeypatch.setenv("VIGIL_REDPEN_ENABLED", "1")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _connected(threshold=BlockThreshold.CRITICAL_HIGH, *, org=ORG, iid=42):
    """A spine with ONE owner-signed connection, and the least-privilege READ registry over it."""
    s = _store()
    ConnectedRepoRegistry(s, owner_key=OWNER, trusted_pubkey=OP).connect(
        org, iid, REPO, block_threshold=threshold, issued_at=float(next(_c)))
    return ConnectedRepoRegistry(s, owner_key=None, trusted_pubkey=OP)


def _outcome(*sevs, refused="", lead_count=0, **extra):
    o = {"schema": rc.REVIEW_OUTCOME_SCHEMA, "repo": REPO, "org_id": ORG, "head_sha": HEAD, "pr_number": 7,
         "slug": "cust_x", "delivery_id": "work-1", "fact_severities": list(sevs),
         "facts": [{"bug_class": "sqli", "severity": s, "finding_ref": f"r{i}", "file": "a.py", "line": 1,
                    "confirmed_by": "sql_injection_breakout"} for i, s in enumerate(sevs)],
         "lead_count": lead_count, "refused": bool(refused), "reason": refused}
    o.update(extra)
    return o


class _FakeGitHub:
    def __init__(self):
        self.mints = []
        self.posts = []

    def mint(self, iid, **kw):
        self.mints.append(iid)
        return {"token": "ghs_tok"}

    def post(self, token, repo, **kw):
        self.posts.append({"token": token, "repo": repo, **kw})
        return {"id": 777}


# ---- the decision: only FACT severities, under the per-repo threshold --------------------------------

@pytest.mark.parametrize("sev", ["critical", "high"])
def test_critical_high_blocks_a_reproduced_critical_or_high_fact(sev):
    d = rc.redpen_check_decision(_outcome(sev, "low"), threshold=BlockThreshold.CRITICAL_HIGH)
    assert d["conclusion"] == "failure" and d["blocking"] is True and d["status"] == "completed"
    assert d["blocking_count"] == 1 and d["fact_count"] == 2


def test_critical_high_does_not_block_medium_or_low_facts():
    d = rc.redpen_check_decision(_outcome("medium", "low"), threshold=BlockThreshold.CRITICAL_HIGH)
    assert d["conclusion"] == "neutral" and d["blocking"] is False and d["fact_count"] == 2


def test_medium_up_blocks_a_medium_fact():
    d = rc.redpen_check_decision(_outcome("medium"), threshold=BlockThreshold.MEDIUM_UP)
    assert d["conclusion"] == "failure" and d["blocking"] is True


def test_none_never_blocks_even_a_critical_fact():
    d = rc.redpen_check_decision(_outcome("critical"), threshold=BlockThreshold.NONE)
    assert d["conclusion"] == "neutral" and d["blocking"] is False


def test_a_clean_review_is_success():
    d = rc.redpen_check_decision(_outcome(), threshold=BlockThreshold.MEDIUM_UP)
    assert d["conclusion"] == "success" and d["blocking"] is False


def test_a_refused_review_is_neutral_with_its_reason():
    d = rc.redpen_check_decision(_outcome(refused="this repository has reached its monthly review spending limit"),
                                 threshold=BlockThreshold.CRITICAL_HIGH)
    assert d["conclusion"] == "neutral" and d["blocking"] is False and "monthly review spending limit" in d["summary"]


def test_a_lead_can_never_block():
    # LEADs never appear in fact_severities; a smuggled "leads" field and a high lead_count are both ignored.
    o = _outcome(lead_count=9, leads=[{"severity": "critical"}, {"severity": "high"}])
    d = rc.redpen_check_decision(o, threshold=BlockThreshold.MEDIUM_UP)
    assert d["conclusion"] == "success" and d["blocking"] is False and d["fact_count"] == 0


def test_an_unknown_threshold_falls_to_the_strictest_default_not_never_block():
    d = rc.redpen_check_decision(_outcome("high"), threshold="bogus")
    assert d["conclusion"] == "failure" and d["blocking"] is True


def test_unknown_severity_values_never_block():
    d = rc.redpen_check_decision(_outcome("urgent", "SEVERE"), threshold=BlockThreshold.MEDIUM_UP)
    assert d["conclusion"] == "success" and d["fact_count"] == 0


_FORBIDDEN = re.compile(r"\b(claude|anthropic|opus|sonnet|haiku|fable|strix|nyx|ultracode|gpt|openai|llm)\b", re.I)
_MONEY = re.compile(r"[$€£]|\b(usd|eur|gbp|cents?|dollars?)\b", re.I)


def test_the_customer_facing_check_copy_names_no_engine_and_quotes_no_amount():
    cases = [_outcome("critical", "high", "medium"), _outcome("low"), _outcome(),
             _outcome(refused="insufficient credits to start a review: top up your wallet to continue")]
    for o in cases:
        for th in BlockThreshold:
            d = rc.redpen_check_decision(o, threshold=th)
            blob = d["title"] + " " + d["summary"]
            assert not _FORBIDDEN.search(blob), _FORBIDDEN.search(blob)
            assert not _MONEY.search(blob), _MONEY.search(blob)


# ---- the write: the owner-signed record is the SOLE source of threshold + installation ----------------

def test_the_threshold_and_installation_come_from_the_owner_signed_record():
    gh = _FakeGitHub()
    reg = _connected(BlockThreshold.MEDIUM_UP, iid=4242)
    out = rc.write_redpen_check(_outcome("medium"), registry=reg, _mint_token=gh.mint, _post_check=gh.post)
    assert out["conclusion"] == "failure" and out["blocking"] is True        # MEDIUM_UP from the signed record
    assert gh.mints == [4242]                                                # the RECORD's installation
    assert gh.posts[0]["head_sha"] == HEAD and gh.posts[0]["conclusion"] == "failure"
    gh2 = _FakeGitHub()
    out2 = rc.write_redpen_check(_outcome("critical"), registry=_connected(BlockThreshold.NONE), _mint_token=gh2.mint,
                                 _post_check=gh2.post)
    assert out2["conclusion"] == "neutral"                                   # NONE from the signed record


def test_an_unconnected_repo_or_another_orgs_record_refuses_before_any_token():
    gh = _FakeGitHub()
    with pytest.raises(rc.RedpenCheckError, match="not connected"):
        rc.write_redpen_check(_outcome("high"), registry=ConnectedRepoRegistry(_store(), owner_key=None,
                                                                               trusted_pubkey=OP),
                              _mint_token=gh.mint, _post_check=gh.post)
    with pytest.raises(rc.RedpenCheckError, match="not connected"):           # connected, but for org_b
        rc.write_redpen_check(_outcome("high"), registry=_connected(org="org_b"), _mint_token=gh.mint,
                              _post_check=gh.post)
    assert gh.mints == [] and gh.posts == []


@pytest.mark.parametrize("bad", [
    {"schema": "something.else"}, {"org_id": ""}, {"repo": ""}, {"head_sha": "not-a-sha"}, {"head_sha": ""},
])
def test_a_malformed_outcome_refuses_before_any_token(bad):
    gh = _FakeGitHub()
    with pytest.raises(rc.RedpenCheckError):
        rc.write_redpen_check(_outcome("high", **bad), registry=_connected(), _mint_token=gh.mint,
                              _post_check=gh.post)
    assert gh.mints == [] and gh.posts == []


def test_red_pen_off_refuses_the_write_even_with_injected_seams(monkeypatch):
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED")
    gh = _FakeGitHub()
    with pytest.raises(rc.RedpenCheckError, match="Red-Pen is off"):
        rc.write_redpen_check(_outcome("high"), registry=_connected(), _mint_token=gh.mint, _post_check=gh.post)
    assert gh.mints == [] and gh.posts == []


def test_end_to_end_the_app_writes_the_blocking_check_through_a_fake_github(monkeypatch):
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode("ascii")
    monkeypatch.setenv("VIGIL_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("VIGIL_GITHUB_APP_PRIVATE_KEY", pem)
    calls = []

    def fake(method, url, *, headers, body):
        calls.append((method, url, headers["Authorization"], json.loads(body.decode()) if body else None))
        if url.endswith("/access_tokens"):
            return {"token": "ghs_installation", "expires_at": "2026-11-17T01:00:00Z"}
        return {"id": 777, "status": "completed"}

    out = rc.write_redpen_check(_outcome("high"), registry=_connected(iid=42), now=1_000_000, transport=fake)
    (mint_m, mint_url, mint_auth, _), (post_m, post_url, post_auth, post_body) = calls
    assert mint_m == "POST" and mint_url == "https://api.github.com/app/installations/42/access_tokens"
    assert mint_auth.startswith("Bearer ")                                    # the App JWT mints the token
    assert post_m == "POST" and post_url == "https://api.github.com/repos/acme/widgets/check-runs"
    assert post_auth == "token ghs_installation"                              # the installation token writes it
    assert post_body["name"] == "VIGIL Red-Pen" and post_body["head_sha"] == HEAD
    assert post_body["status"] == "completed" and post_body["conclusion"] == "failure"
    assert out["ok"] and out["blocking"] is True and out["check_run"]["id"] == 777


# ---- producer ⟷ consumer contract (offense builder + spooler → sovereign decision/drain) ---------------

def _job():
    return SecurityJob(source="webhook", repo=REPO, commit=HEAD, pr_number=7, profile="redpen", delivery_id="w")


def _fact(sev):
    return RedPenFact(bug_class="sqli", confirmed_by="sql_injection_breakout", severity=sev, finding_ref=f"r-{sev}",
                      reason="r", lens="injection", file="a.py", line=3)


def test_the_offense_outcome_builder_and_the_sovereign_decision_agree():
    report = RedPenReport(enabled=True, facts=(_fact("high"),),
                          leads=(RedPenLead(bug_class="xss", severity="critical", finding_ref="lead", reason="r",
                                            lens="client_side"),))
    env = build_review_outcome(_job(), report, slug="cust_x", org_id=ORG)
    assert rc.redpen_check_decision(env, threshold=BlockThreshold.CRITICAL_HIGH)["conclusion"] == "failure"
    leads_only = build_review_outcome(_job(), RedPenReport(enabled=True, leads=report.leads), slug="cust_x",
                                      org_id=ORG)
    # a CRITICAL lead alone can never block — it never crosses the plane boundary as a severity
    assert rc.redpen_check_decision(leads_only, threshold=BlockThreshold.MEDIUM_UP)["conclusion"] == "success"


# ---- the outcome drain ------------------------------------------------------------------------------

def _spool(tmp_path: Path) -> Path:
    return tmp_path / "redpen-outcomes"


def _emit(tmp_path: Path, env: dict) -> None:
    make_inert_spooler(str(_spool(tmp_path)))(env)


def test_the_drain_writes_the_check_and_archives_the_outcome(tmp_path):
    gh = _FakeGitHub()
    _emit(tmp_path, build_review_outcome(_job(), RedPenReport(enabled=True, facts=(_fact("critical"),)),
                                         slug="cust_x", org_id=ORG))
    drain = rc.RedpenOutcomeDrain(spool_dir=_spool(tmp_path), registry=_connected(), _mint_token=gh.mint,
                                  _post_check=gh.post)
    assert drain.drain() == {"written": 1, "blocked": 1, "rejected": 0, "deferred": 0}
    assert gh.posts[0]["conclusion"] == "failure"
    assert list((_spool(tmp_path) / "incoming").glob("*.json")) == []
    assert len(list((_spool(tmp_path) / "processed").glob("*.json"))) == 1
    assert drain.drain()["written"] == 0                                      # nothing left: written once


def test_the_drain_quarantines_a_definitive_refusal(tmp_path):
    gh = _FakeGitHub()
    _emit(tmp_path, _outcome("high", org_id="org_nobody"))                    # not connected for that org
    inc = _spool(tmp_path) / "incoming"
    (inc / "garbage.json").write_text("[" * 50000 + "]" * 50000, encoding="utf-8")   # pathologically nested
    drain = rc.RedpenOutcomeDrain(spool_dir=_spool(tmp_path), registry=_connected(), _mint_token=gh.mint,
                                  _post_check=gh.post)
    out = drain.drain()
    assert out["rejected"] == 2 and out["written"] == 0 and gh.posts == []
    assert len(list((_spool(tmp_path) / "rejected").glob("*.reason"))) == 2


def test_the_drain_retries_an_egress_failure_a_bounded_number_of_times(tmp_path):
    def failing_post(token, repo, **kw):
        raise rc._app.GitHubAppError("GitHub 502")

    gh = _FakeGitHub()
    _emit(tmp_path, _outcome("high"))
    drain = rc.RedpenOutcomeDrain(spool_dir=_spool(tmp_path), registry=_connected(), _mint_token=gh.mint,
                                  _post_check=failing_post)
    for _ in range(rc._MAX_WRITE_ATTEMPTS - 1):
        assert drain.drain() == {"written": 0, "blocked": 0, "rejected": 0, "deferred": 1}   # kept, retried
    assert len(list((_spool(tmp_path) / "incoming").glob("*.json"))) == 1
    assert drain.drain()["rejected"] == 1                                     # the bound reached → quarantined
    assert list((_spool(tmp_path) / "incoming").glob("*.json")) == []


def test_a_transient_failure_then_success_writes_once(tmp_path):
    flaky = {"n": 0}
    gh = _FakeGitHub()

    def post(token, repo, **kw):
        flaky["n"] += 1
        if flaky["n"] == 1:
            raise rc._app.GitHubAppError("GitHub 503")
        return gh.post(token, repo, **kw)

    _emit(tmp_path, _outcome("high"))
    drain = rc.RedpenOutcomeDrain(spool_dir=_spool(tmp_path), registry=_connected(), _mint_token=gh.mint,
                                  _post_check=post)
    assert drain.drain()["deferred"] == 1
    assert drain.drain()["written"] == 1 and len(gh.posts) == 1


def test_the_drain_reclaims_a_crashed_claim(tmp_path):
    gh = _FakeGitHub()
    _emit(tmp_path, _outcome("high"))
    sp = _spool(tmp_path)
    drain = rc.RedpenOutcomeDrain(spool_dir=sp, registry=_connected(), _mint_token=gh.mint, _post_check=gh.post)
    (f,) = list((sp / "incoming").glob("*.json"))
    f.rename(sp / "working" / f.name)                                         # a claimer died mid-process
    assert drain.drain()["written"] == 1


def test_the_drain_is_a_no_op_when_red_pen_is_off(tmp_path, monkeypatch):
    gh = _FakeGitHub()
    _emit(tmp_path, _outcome("high"))
    monkeypatch.delenv("VIGIL_REDPEN_ENABLED")
    drain = rc.RedpenOutcomeDrain(spool_dir=_spool(tmp_path), registry=_connected(), _mint_token=gh.mint,
                                  _post_check=gh.post)
    assert drain.drain() == {"written": 0, "blocked": 0, "rejected": 0, "deferred": 0}
    assert len(list((_spool(tmp_path) / "incoming").glob("*.json"))) == 1     # untouched — nothing quarantined
    assert gh.posts == []
