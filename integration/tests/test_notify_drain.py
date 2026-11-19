"""PR-D notify_drain — the orchestrator that delivers NEW FACT findings + syncs issues, tenant-isolated.

Load-bearing invariants proven here:
  * FLAG OFF = TOTAL NO-OP (byte-identical-off): drain_once(enabled=False) touches NONE of the injected deps.
  * TENANT ISOLATION (self-red-pen "cross-tenant leak"): a finding whose engagement_slug is NOT the org's own
    server-derived slug is REJECTED and never delivered — even if a buggy/hostile injected reader returns it.
    MUTATION-VERIFY: deleting the `slug not in slug_set` guard REDS test_cross_tenant_reader_is_rejected.
  * IDEMPOTENCY: an already-delivered finding is skipped; a TRANSIENT failure is NOT recorded (retried next pass).
  * NO SPINE WRITE: the drain's only side effects are the injected ledger calls (never a finding mint).

The drain never imports sigil/framework — ALL sovereign logic is injected; these tests wire fakes.
"""
from __future__ import annotations

import ast
import pathlib

from vigil_integration.jobs import notify_drain as nd


def test_drain_imports_no_sovereign_or_offense_module():
    # The drain stays plane-pure: a STATIC scan of its import graph (incl. any lazy in-function import) must show
    # NO sigil (integration is vigil_core-only) and NO engine. This is what keeps the sovereignty boundary intact
    # while all sovereign logic is injected.
    tree = ast.parse(pathlib.Path(nd.__file__).read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    assert "sigil" not in mods, f"notify_drain must not import sigil: {sorted(mods)}"
    assert "framework" not in mods and "strix" not in mods, f"notify_drain must not import the engine: {sorted(mods)}"


def _finding(slug, ref, *, cleared=False):
    row = {"engagement_slug": slug, "finding_ref": ref, "oracle_context_digest": "d-" + ref,
           "title": "t-" + ref, "severity": "high"}
    if cleared:
        row["retest"] = {"status": "fixed"}
    return row


def _deps(*, slug_sets, findings, channels=None, delivered_init=None, deliver_fn=None,
          plan=None, apply=None):
    """Build DrainDeps over in-memory fakes. `calls` records every dep invocation so a test can assert the flag-off
    no-op touched nothing."""
    calls = {"slug": [], "find": [], "chan": [], "deliver": [], "already": [], "record": [], "plan": [], "apply": []}
    delivered = set(delivered_init or set())

    def slug_set_for(org):
        calls["slug"].append(org)
        return set(slug_sets.get(org, set()))

    def findings_for(org, slug_set):
        calls["find"].append((org, frozenset(slug_set)))
        return list(findings.get(org, []))

    def channels_for(org):
        calls["chan"].append(org)
        return list((channels or {}).get(org, ["ch"]))

    def deliver(org, channel, finding):
        calls["deliver"].append((org, channel, finding["finding_ref"]))
        return (deliver_fn or (lambda o, c, f: nd.DeliverOutcome(ok=True)))(org, channel, finding)

    def already_delivered(org, identity):
        calls["already"].append((org, identity))
        return (org, identity) in delivered

    def record_delivery(org, identity):
        calls["record"].append((org, identity))
        delivered.add((org, identity))

    def plan_issues(org, fs):
        calls["plan"].append((org, [f["finding_ref"] for f in fs]))
        return (plan or (lambda o, f: []))(org, fs)

    def apply_issue(org, action):
        calls["apply"].append((org, action))
        return (apply or (lambda o, a: ""))(org, action)

    deps = nd.DrainDeps(
        slug_set_for=slug_set_for, findings_for=findings_for, channels_for=channels_for, deliver=deliver,
        already_delivered=already_delivered, record_delivery=record_delivery,
        plan_issues=plan_issues if plan is not None else None,
        apply_issue=apply_issue if apply is not None else None)
    return deps, calls, delivered


def test_flag_off_is_total_noop_byte_identical():
    deps, calls, _ = _deps(slug_sets={"acme": {"cust_acme"}}, findings={"acme": [_finding("cust_acme", "F1")]})
    res = nd.drain_once(deps, ["acme"], now=1.0, enabled=False)
    assert res == nd.DrainResult()                         # empty result
    assert all(v == [] for v in calls.values()), "flag-off drain must call NO dep"


def test_delivers_new_findings_and_is_idempotent():
    deps, calls, delivered = _deps(slug_sets={"acme": {"cust_acme"}},
                                   findings={"acme": [_finding("cust_acme", "F1"), _finding("cust_acme", "F2")]})
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.delivered == 2 and res.sends_ok == 2 and res.errors == 0
    assert len(calls["deliver"]) == 2 and len(calls["record"]) == 2
    # second pass: both already delivered -> skipped, no new sends
    res2 = nd.drain_once(deps, ["acme"], now=2.0)
    assert res2.delivered == 0 and res2.skipped == 2 and res2.sends_ok == 0


def test_cross_tenant_reader_is_rejected_SELF_RED_PEN():
    # A HOSTILE/BUGGY reader returns org "acme" a finding whose slug belongs to another tenant. The structural
    # re-check must REJECT it: it is never delivered and never recorded. MUTATION-VERIFY: removing the
    # `slug not in slug_set` guard in drain_once makes this finding deliver -> this test REDS.
    deps, calls, delivered = _deps(slug_sets={"acme": {"cust_acme"}},
                                   findings={"acme": [_finding("cust_EVIL", "X1"), _finding("cust_acme", "F1")]})
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.rejected_cross_tenant == 1 and res.errors >= 1
    assert res.delivered == 1                               # only the org's OWN finding was delivered
    refs_delivered = {ref for (_o, _c, ref) in calls["deliver"]}
    assert refs_delivered == {"F1"} and "X1" not in refs_delivered
    assert all(ident[1] != "X1" for (_o, ident) in calls["record"])   # the foreign finding was never recorded


def test_transient_failure_is_not_recorded_and_retries():
    state = {"fail": True}

    def flaky(org, channel, finding):
        if state["fail"]:
            return nd.DeliverOutcome(ok=False, transient=True)
        return nd.DeliverOutcome(ok=True)

    deps, calls, delivered = _deps(slug_sets={"acme": {"cust_acme"}},
                                   findings={"acme": [_finding("cust_acme", "F1")]}, deliver_fn=flaky)
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.delivered == 0 and res.errors >= 1 and calls["record"] == []   # transient -> not recorded
    # the failure clears; next pass delivers and records it
    state["fail"] = False
    res2 = nd.drain_once(deps, ["acme"], now=2.0)
    assert res2.delivered == 1 and len(calls["record"]) == 1


def test_definitive_failure_is_recorded_not_retried_forever():
    deps, calls, delivered = _deps(slug_sets={"acme": {"cust_acme"}},
                                   findings={"acme": [_finding("cust_acme", "F1")]},
                                   deliver_fn=lambda o, c, f: nd.DeliverOutcome(ok=False, transient=False))
    res = nd.drain_once(deps, ["acme"], now=1.0)
    # a definitive (non-transient) failure is counted but recorded, so the drain does not spin on it forever
    assert res.errors >= 1 and len(calls["record"]) == 1


def test_no_slug_set_is_fail_closed():
    deps, calls, _ = _deps(slug_sets={"acme": set()}, findings={"acme": [_finding("cust_acme", "F1")]})
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.delivered == 0 and calls["find"] == []     # no proven host -> no read, no delivery


def test_issue_sync_opens_and_closes():
    def plan(org, fs):
        return [("open", f) for f in fs if not f.get("retest")] + \
               [("close", f) for f in fs if f.get("retest", {}).get("status") == "fixed"]

    def apply(org, action):
        return action[0]   # "open" | "close"

    deps, calls, _ = _deps(slug_sets={"acme": {"cust_acme"}},
                           findings={"acme": [_finding("cust_acme", "F1"), _finding("cust_acme", "F2", cleared=True)]},
                           plan=plan, apply=apply)
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.issues_opened == 1 and res.issues_closed == 1


def test_deliver_exception_is_isolated():
    def boom(org, channel, finding):
        raise RuntimeError("channel down")

    deps, calls, _ = _deps(slug_sets={"acme": {"cust_acme"}},
                           findings={"acme": [_finding("cust_acme", "F1")]}, deliver_fn=boom)
    res = nd.drain_once(deps, ["acme"], now=1.0)
    assert res.errors >= 1 and res.delivered == 0     # the exception was caught; the pass survived
