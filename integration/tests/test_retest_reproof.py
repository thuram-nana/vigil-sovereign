"""C1b completion — the KEYLESS OFFENSE half of the customer LIVE retest re-proof.

The sovereign (``sigil.ui.provision.retest``) publishes an owner-signed re-proof TICKET (finding identity + an
owner-signed ``CreditLaunchLease``) to the ``retest-reproof`` seam. This suite pins the offense half:

  * the WIRE CONTRACT (``vigil_core.retest_reproof``) — ticket / outcome builders, fail-closed;
  * the TRIGGER — one ``SecurityJob`` per well-formed ticket, malformed skipped (produces, never runs);
  * the WORKER — binds the host AUTHORITATIVELY from the VERIFIED customer authority (never the ticket),
    VERIFIES the ticket-carried owner-signed lease BEFORE any traffic, re-fires THAT finding's proof against the
    verified host and maps the verdict: ``cleared`` ONLY on DECISIVE clearance (every run completed, none fired —
    R5 ``refire_reproduction`` positive evidence); a fire ⇒ ``still_present``; silence / timeout / unavailable
    sandbox / no recipe ⇒ ``inconclusive`` (NEVER cleared); a lease that will not verify ⇒ ``unavailable``;
  * the GATE + ``JobRunner.run_one`` — the real customer-authority gate (minus the launch-seam lease conjunct).

Framework (offense) is imported lazily by the worker/gate; run in the offense CI leg (same posture as
test_engage_runner / test_redpen_retest).
"""
from __future__ import annotations

import datetime as _dt
import json
import tempfile
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, retest_reproof_outcome, retest_reproof_ticket,
    sign_credit_launch_lease, ticket_identity,
)
from vigil_core.retest_reproof import CLEARED, INCONCLUSIVE, STILL_PRESENT, UNAVAILABLE
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.retest_reproof import (
    RETEST_OUTCOME_SEAM_SUBDIR, RETEST_REPROOF_SEAM_SUBDIR, RetestReproofTrigger, _job_from_ticket,
    build_retest_reproof_gate, make_retest_reproof_worker, retest_reproof_jobs_from_seam,
)

pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in the sovereign leg")

SLUG, HOST, ORG = "cust_abc123", "apme.cm", "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease_doc(owner, *, nonce="n1", issued=1000.0, units=200, slug=SLUG, host=HOST, org=ORG):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=units,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=1),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _ticket(owner, *, nonce="n1", ref="F1", digest="d1", slug=SLUG, host=HOST, org=ORG, issued=1000.0):
    lease = _lease_doc(owner, nonce=nonce, issued=issued, slug=slug, host=host, org=org).model_dump(mode="json")
    return retest_reproof_ticket(slug=slug, host=host, org_id=org, finding_ref=ref, nonce=nonce, lease=lease,
                                 oracle_context_digest=digest, bug_class="xss")


def _publish(base, ticket):
    seam = Path(base) / RETEST_REPROOF_SEAM_SUBDIR
    seam.mkdir(parents=True, exist_ok=True)
    (seam / f"{ticket['nonce']}.json").write_text(json.dumps(ticket), encoding="utf-8")


def _outcome_on_seam(base, nonce):
    p = Path(base) / RETEST_OUTCOME_SEAM_SUBDIR / f"{nonce}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _job(owner, **kw):
    t = _ticket(owner, **kw)
    return _job_from_ticket(t)


def _authority(scope=(HOST,), issued_by="customer:org_a", env="twin"):
    return SimpleNamespace(issued_by=issued_by, scope=list(scope), environment=env)


def _real_authority(scope=(HOST,), *, issued_by="customer:org_a", env="twin", now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)
    return EngagementAuthority(engagement_slug=SLUG, environment=env, scope=list(scope), issued_by=issued_by,
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _unavailable_sandbox(cmd):
    from vigil_integration.live.sandbox_exec import SandboxUnavailable
    raise SandboxUnavailable("no bwrap")


# ---- the sandbox fakes (R5 shapes) -------------------------------------------------------------------
def _sandbox_outcome(**kw):
    from vigil_integration.live.sandbox_exec import SandboxOutcome
    return SandboxOutcome(**kw)


def _recipe(markers=("PWNED",), cmd="python3 poc.py"):
    from vigil_integration.redpen import LensCandidate
    return LensCandidate(lens="injection", bug_class="command_injection", channel="process",
                         poc_command=cmd, fire_markers=markers)


def _seq(*outcomes):
    it = iter(outcomes)
    return lambda cmd: next(it)


# ---- the wire contract -------------------------------------------------------------------------------
def test_ticket_builder_is_fail_closed():
    good = _ticket(generate_keypair())
    assert good["slug"] == SLUG and good["host"] == HOST and good["finding_ref"] == "F1"
    lease = good["lease"]
    for bad in ([{"slug": "", "host": HOST, "org_id": ORG, "finding_ref": "F", "nonce": "n", "lease": lease}],
                [{"slug": SLUG, "host": "", "org_id": ORG, "finding_ref": "F", "nonce": "n", "lease": lease}],
                [{"slug": SLUG, "host": HOST, "org_id": ORG, "finding_ref": "", "nonce": "n", "lease": lease}],
                [{"slug": SLUG, "host": HOST, "org_id": ORG, "finding_ref": "F", "nonce": "", "lease": lease}],
                [{"slug": SLUG, "host": HOST, "org_id": ORG, "finding_ref": "F", "nonce": "n", "lease": None}]):
        with pytest.raises(ValueError):
            retest_reproof_ticket(**bad[0])


def test_outcome_builder_rejects_an_unknown_verdict():
    assert retest_reproof_outcome(slug=SLUG, finding_ref="F1", nonce="n", verdict=CLEARED)["verdict"] == CLEARED
    with pytest.raises(ValueError):
        retest_reproof_outcome(slug=SLUG, finding_ref="F1", nonce="n", verdict="fixed")   # not a wire verdict
    with pytest.raises(ValueError):
        retest_reproof_outcome(slug="", finding_ref="F1", nonce="n", verdict=CLEARED)


def test_ticket_identity_matches_outcome_identity():
    owner = generate_keypair()
    t = _ticket(owner, nonce="n9", ref="F2", digest="d2")
    o = retest_reproof_outcome(slug=SLUG, finding_ref="F2", nonce="n9", verdict=CLEARED, oracle_context_digest="d2")
    assert ticket_identity(t) == ticket_identity(o) == (SLUG, "F2", "d2", "n9")


# ---- the trigger -------------------------------------------------------------------------------------
def test_trigger_produces_one_job_per_valid_ticket(tmp_path):
    owner = generate_keypair()
    _publish(tmp_path, _ticket(owner, nonce="n1", ref="F1"))
    _publish(tmp_path, _ticket(owner, nonce="n2", ref="F2", digest="d2"))
    jobs = retest_reproof_jobs_from_seam(str(tmp_path))
    by = {j.extra["nonce"]: j for j in jobs}
    assert set(by) == {"n1", "n2"}
    assert by["n1"].slug == SLUG and by["n1"].extra["finding_ref"] == "F1" and by["n1"].tenant_id == ORG
    assert by["n1"].extra["retest_reproof"] is True and isinstance(by["n1"].extra["lease"], dict)
    assert by["n1"].delivery_id == f"retest-reproof:{SLUG}:n1"       # content-addressed exactly-once


def test_trigger_skips_a_malformed_ticket(tmp_path):
    seam = tmp_path / RETEST_REPROOF_SEAM_SUBDIR
    seam.mkdir(parents=True)
    (seam / "bad.json").write_text("{not json", encoding="utf-8")
    (seam / "nolease.json").write_text(json.dumps({"slug": SLUG, "host": HOST, "org_id": ORG, "finding_ref": "F1",
                                                   "nonce": "n"}), encoding="utf-8")   # no lease -> skipped
    (seam / "noref.json").write_text(json.dumps({"slug": SLUG, "host": HOST, "org_id": ORG, "nonce": "n",
                                                 "lease": {"x": 1}}), encoding="utf-8")   # no finding_ref -> skipped
    assert retest_reproof_jobs_from_seam(str(tmp_path)) == []
    assert RetestReproofTrigger(str(tmp_path)).poll() == []


# ---- the worker: the verdict mapping (deterministic; authority + lease injected) ---------------------
def _worker(**kw):
    kw.setdefault("_load_authority", lambda slug: _authority())
    kw.setdefault("_verify_lease", lambda lease, **_k: (True, "ok"))
    kw.setdefault("checkout", lambda job: "/root")
    return make_retest_reproof_worker(**kw)


def test_decisive_clearance_is_cleared(tmp_path):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(),
                _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="ok", stderr=""),
                              _sandbox_outcome(exit_code=0, stdout="ok", stderr="")))
    out = w(_job(owner))
    assert out["verdict"] == CLEARED                                  # every run completed, none fired
    assert _outcome_on_seam(str(tmp_path), "n1")["verdict"] == CLEARED


def test_a_fire_is_still_present(tmp_path):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(),
                _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="PWNED", stderr="")))
    assert w(_job(owner))["verdict"] == STILL_PRESENT


@pytest.mark.parametrize("make_sandbox,why", [
    (lambda: _seq(_sandbox_outcome(exit_code=None, stdout="", stderr="", timed_out=True)), "a timed-out run"),
    (lambda: _unavailable_sandbox, "unavailable sandbox"),
])
def test_silence_is_never_cleared(tmp_path, make_sandbox, why):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(), _sandbox=make_sandbox())
    out = w(_job(owner))
    assert out["verdict"] == INCONCLUSIVE and out["verdict"] != CLEARED, why


def test_no_retained_proof_is_inconclusive_never_cleared(tmp_path):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: None)   # no re-fireable recipe
    assert w(_job(owner))["verdict"] == INCONCLUSIVE


def test_a_lease_that_will_not_verify_is_unavailable_never_cleared(tmp_path):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(),
                _verify_lease=lambda lease, **_k: (False, "lease does not verify"),
                _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="ok", stderr="")))
    out = w(_job(owner))
    assert out["verdict"] == UNAVAILABLE                              # refused BEFORE any re-fire
    assert out["reason"].startswith("retest lease did not verify")


def test_the_host_is_bound_from_the_authority_not_the_ticket(tmp_path):
    # a ticket naming a different host than the verified authority: the lease verify (and the re-fire) use the
    # AUTHORITY host, so a forged ticket host can never widen scope.
    owner = generate_keypair()
    seen = {}

    def _vl(lease_json, *, slug, host, tenant, base_dir, now, nonce):
        seen["host"] = host
        return (True, "ok")
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(), _verify_lease=_vl,
                _load_authority=lambda slug: _authority(scope=["real.example"]),
                _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="ok", stderr="")))
    w(_job(owner, host="attacker.example"))                          # ticket says attacker.example
    assert seen["host"] == "real.example"                            # but the authority's host is used


def test_a_non_customer_authority_is_unavailable(tmp_path):
    owner = generate_keypair()
    w = _worker(base_dir=str(tmp_path), proof_resolver=lambda s, r: _recipe(),
                _load_authority=lambda slug: _authority(issued_by="operator:ops"))
    assert w(_job(owner))["verdict"] == UNAVAILABLE


def test_a_non_retest_job_is_refused():
    owner = generate_keypair()
    job = SecurityJob.normalize(source="api", repo=HOST, engagement_slug=SLUG, tenant_id=ORG, extra={"nonce": "n"})
    with pytest.raises(ValueError):
        _worker(proof_resolver=lambda s, r: _recipe())(job)


# ---- the worker with the REAL lease verify + REAL re-fire (framework authority monkeypatched) ---------
def _pin(monkeypatch, owner, *, authority=None):
    from framework.v2.authority import store as authz_store
    auth = authority if authority is not None else _real_authority()
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: auth)


def test_real_lease_verify_and_refire_clears_a_fixed_finding(tmp_path, monkeypatch):
    owner = generate_keypair()
    _pin(monkeypatch, owner)
    w = make_retest_reproof_worker(base_dir=str(tmp_path), checkout=lambda job: "/root",
                                   proof_resolver=lambda s, r: _recipe(), now=1000.0,
                                   _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="clean", stderr=""),
                                                 _sandbox_outcome(exit_code=0, stdout="clean", stderr="")))
    assert w(_job(owner, issued=1000.0))["verdict"] == CLEARED       # real owner-pin lease verify + real refire


def test_real_lease_verify_rejects_a_settled_lease(tmp_path, monkeypatch):
    from vigil_integration.live.credit_lease_broker import record_lease_settlement
    owner = generate_keypair()
    _pin(monkeypatch, owner)
    record_lease_settlement(str(tmp_path), SLUG, "n1")               # the lease is already settled/canceled
    w = make_retest_reproof_worker(base_dir=str(tmp_path), checkout=lambda job: "/root",
                                   proof_resolver=lambda s, r: _recipe(), now=1000.0,
                                   _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="clean", stderr="")))
    out = w(_job(owner, issued=1000.0))
    assert out["verdict"] == UNAVAILABLE and "settled" in out["reason"]


def test_real_lease_verify_rejects_a_wrong_tenant_lease(tmp_path, monkeypatch):
    owner = generate_keypair()
    _pin(monkeypatch, owner)
    w = make_retest_reproof_worker(base_dir=str(tmp_path), checkout=lambda job: "/root",
                                   proof_resolver=lambda s, r: _recipe(), now=1000.0,
                                   _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="clean", stderr="")))
    # a FORGED ticket: the job runs under tenant ORG, but it carries a lease owner-signed for a DIFFERENT org —
    # the bind (lease.org_id == job tenant) refuses, so the forged pairing sends no traffic.
    lease = _lease_doc(owner, org="org_other").model_dump(mode="json")
    ticket = retest_reproof_ticket(slug=SLUG, host=HOST, org_id=ORG, finding_ref="F1", nonce="n1", lease=lease,
                                   oracle_context_digest="d1", bug_class="xss")
    out = w(_job_from_ticket(ticket))
    assert out["verdict"] == UNAVAILABLE


# ---- the gate + JobRunner.run_one (the real scheduling path) ------------------------------------------
def test_gate_refuses_a_non_customer_authority(monkeypatch):
    owner = generate_keypair()
    from framework.v2.authority import store as authz_store
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _authority(issued_by="operator:ops"))
    gate = build_retest_reproof_gate(now=1000.0)
    out = gate(_job(owner))
    assert out.allowed is False


def test_run_one_drives_the_worker_under_the_gate(tmp_path, monkeypatch):
    from vigil_integration.jobs.queue import SecurityJobQueue
    from vigil_integration.jobs.runner import JobRunner
    owner = generate_keypair()
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)                       # shard for org_a so _reconcile_tenant matches
    _pin(monkeypatch, owner)
    gate_now = _dt.datetime.fromtimestamp(1000.0, tz=timezone.utc)   # authorize_action takes a datetime
    gate = build_retest_reproof_gate(now=gate_now)
    worker = make_retest_reproof_worker(base_dir=str(tmp_path), checkout=lambda job: "/root",
                                        proof_resolver=lambda s, r: _recipe(), now=1000.0,   # lease verify: a float ts
                                        _sandbox=_seq(_sandbox_outcome(exit_code=0, stdout="ok", stderr=""),
                                                      _sandbox_outcome(exit_code=0, stdout="ok", stderr="")))
    q = SecurityJobQueue(str(tmp_path / "q"))
    q.enqueue(_job(owner, issued=1000.0))
    outcome = JobRunner(queue=q, gate=gate, worker=worker, assert_tenant=lambda: None).run_one()
    assert outcome.state == "done" and outcome.result["verdict"] == CLEARED
    assert _outcome_on_seam(str(tmp_path), "n1")["verdict"] == CLEARED
