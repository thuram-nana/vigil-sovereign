"""
Tests for Workstream D.2 — the OPT-IN access-control check pack.

The pack seeds the seven access-control classes (idor/bola/bfla/broken_access_control/authorization/
mass_assignment/privilege_escalation) behind an explicit ``enabled`` flag, default OFF. Coverage:

  * default-OFF: ``build_access_control_checks`` returns () unless enabled AND configured, so the pack
    is gate-neutral (never in DEFAULT_CHECKS / the library).
  * the two-identity CROSS-READ path fires the achieved-state oracle on a vulnerable target and does
    NOT fire on a correctly-authorised (403) target — for each of the six cross classes.
  * mass-assignment confirms ONLY on a real persisted state change (privileged field present AFTER but
    absent BEFORE), never on a secure app that ignores the field.
  * integration through the real AuditEngine with the seeded checks.

The oracle is the sole authority: a 403 / unchanged object fails the predicate and is never a finding.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.access_control import (
    ACCESS_CONTROL_CLASSES,
    AccessControlConfig,
    CrossAccessSpec,
    MassAssignmentCheck,
    build_access_control_checks,
    default_cross_specs,
)
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind

# The victim's distinctive object content — long enough to clear the oracle's min_len(8) guard and
# specific enough that its appearance in the attacker's response is unambiguous cross-tenant leakage.
_VICTIM_SECRET = "SECRET-BOB-INVOICE-#2-total=$9001-acct=bob@example.test"
_VICTIM_REF = "2"
_REF_PARAM = "id"


def _requested_id(req: HttpRequest) -> str:
    return (parse_qs(urlsplit(req.url).query).get(_REF_PARAM) or [""])[0]


def _make_cross_target(vulnerable: bool):
    """Return ``(attacker_send, victim_send)`` for a two-identity object endpoint. The victim always
    sees its own object (ground truth). The attacker sees it too iff the app is broken; a secure app
    returns 403 with no content."""

    def victim_send(req: HttpRequest) -> dict:
        # bob's own session: he legitimately sees object 2.
        return {"status": 200, "body": _VICTIM_SECRET if _requested_id(req) == _VICTIM_REF else ""}

    def attacker_send(req: HttpRequest) -> dict:
        rid = _requested_id(req)
        if rid == _VICTIM_REF and not vulnerable:
            return {"status": 403, "body": "forbidden"}
        # vulnerable: no object-level check -> alice reads bob's object 2.
        return {"status": 200, "body": _VICTIM_SECRET if rid == _VICTIM_REF else "alice's own object 1"}

    return attacker_send, victim_send


def _obj_template() -> tuple[RequestTemplate, object]:
    req = HttpRequest(method="GET", url=f"http://target.test/obj?{_REF_PARAM}=1", headers=[], body=None)
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == _REF_PARAM)
    return template, point


# --- the opt-in flag (default OFF => gate-neutral) ------------------------------------------------


def test_pack_is_off_by_default() -> None:
    _, victim_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(victim_send=victim_send, cross_specs=default_cross_specs(victim_ref=_VICTIM_REF))
    assert build_access_control_checks(cfg, enabled=False) == ()      # flag off
    assert build_access_control_checks(None, enabled=True) == ()       # no config
    assert build_access_control_checks(cfg) == ()                      # default enabled=False


def test_enabled_pack_builds_all_seven_classes() -> None:
    _, victim_send = _make_cross_target(vulnerable=True)
    ma = MassAssignmentCheck(
        id="ac-ma", field="role", privileged_value="admin",
        readback_send=lambda r: {"status": 200, "body": ""},
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    cfg = AccessControlConfig(
        victim_send=victim_send, cross_specs=default_cross_specs(victim_ref=_VICTIM_REF), mass_assignment=ma)
    checks = build_access_control_checks(cfg, enabled=True)
    classes = {c.bug_class for c in checks}
    assert classes == set(ACCESS_CONTROL_CLASSES)                     # all seven seeded


# --- the two-identity CROSS-READ path (six classes) ----------------------------------------------


def _run_cross(bug_class: str, vulnerable: bool):
    attacker_send, victim_send = _make_cross_target(vulnerable)
    cfg = AccessControlConfig(
        victim_send=victim_send,
        cross_specs=(CrossAccessSpec(bug_class=bug_class, ref_param=_REF_PARAM, victim_ref=_VICTIM_REF),),
    )
    (check,) = build_access_control_checks(cfg, enabled=True)
    template, point = _obj_template()
    ctx = check.probe(template, point, attacker_send)
    assert ctx is not None
    return confirm_finding({"bug_class": bug_class, "title": "", "severity": "High"}, ctx)


def test_vulnerable_target_confirms_each_cross_class_via_achieved_state() -> None:
    for bc in ("idor", "bola", "bfla", "broken_access_control", "authorization", "privilege_escalation"):
        confirmed = _run_cross(bc, vulnerable=True)
        assert confirmed is not None, f"{bc} should confirm on a vulnerable target"
        assert confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
        assert confirmed.bug_class == bc


def test_secure_target_confirms_nothing_for_any_cross_class() -> None:
    for bc in ("idor", "bola", "bfla", "broken_access_control", "authorization", "privilege_escalation"):
        assert _run_cross(bc, vulnerable=False) is None, f"{bc} must not fire on a 403"


# --- mass assignment (persisted state change) ----------------------------------------------------


def _make_mass_assign_target(vulnerable: bool):
    """A stateful object with a ``role`` field. A vulnerable app lets the attacker set ``role`` via
    mass assignment (it persists); a secure app ignores the extra field."""
    state = {"role": "user"}

    def _obj() -> str:
        return '{"id": 1, "name": "alice", "role": "%s"}' % state["role"]

    def mutate_send(req: HttpRequest) -> dict:
        role = (parse_qs(req.body or "").get("role") or [None])[0]
        if role and vulnerable:
            state["role"] = role          # mass assignment accepted + persisted
        return {"status": 200, "body": _obj()}

    def read_send(req: HttpRequest) -> dict:
        return {"status": 200, "body": _obj()}

    return mutate_send, read_send


def _run_mass_assign(vulnerable: bool):
    mutate_send, read_send = _make_mass_assign_target(vulnerable)
    ma = MassAssignmentCheck(
        id="ac-mass-assignment", field="role", privileged_value="admin",
        readback_send=read_send,
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    req = HttpRequest(method="POST", url="http://target.test/me",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")],
                      body="role=user&name=alice")
    template = RequestTemplate(req)
    point = next(p for p in template.insertion_points(kinds=(InsertionKind.BODY_FORM_VALUE,)) if p.name == "role")
    ctx = ma.probe(template, point, mutate_send)
    assert ctx is not None
    return confirm_finding({"bug_class": "mass_assignment", "title": "", "severity": "High"}, ctx)


def test_mass_assignment_confirms_on_a_persisted_privilege_field() -> None:
    confirmed = _run_mass_assign(vulnerable=True)
    assert confirmed is not None and confirmed.confirmed_by == OracleKind.ACHIEVED_STATE
    assert confirmed.bug_class == "mass_assignment"


def test_mass_assignment_does_not_fire_when_the_field_is_ignored() -> None:
    assert _run_mass_assign(vulnerable=False) is None


def test_mass_assignment_only_runs_on_its_field_point() -> None:
    mutate_send, read_send = _make_mass_assign_target(vulnerable=True)
    ma = MassAssignmentCheck(
        id="ac-mass-assignment", field="role", privileged_value="admin",
        readback_send=read_send,
        readback_request=HttpRequest(method="GET", url="http://target.test/me", headers=[], body=None),
    )
    req = HttpRequest(method="POST", url="http://target.test/me",
                      headers=[("Content-Type", "application/x-www-form-urlencoded")], body="name=alice")
    template = RequestTemplate(req)
    name_point = next(p for p in template.insertion_points(kinds=(InsertionKind.BODY_FORM_VALUE,)) if p.name == "name")
    assert ma.probe(template, name_point, mutate_send) is None   # not the role point -> skipped


# --- integration through the real engine ---------------------------------------------------------


def test_seeded_checks_run_through_the_audit_engine() -> None:
    attacker_send, victim_send = _make_cross_target(vulnerable=True)
    cfg = AccessControlConfig(
        victim_send=victim_send,
        cross_specs=(CrossAccessSpec(bug_class="idor", ref_param=_REF_PARAM, victim_ref=_VICTIM_REF),),
    )
    checks = build_access_control_checks(cfg, enabled=True)
    engine = AuditEngine(attacker_send)
    req = HttpRequest(method="GET", url=f"http://target.test/obj?{_REF_PARAM}=1", headers=[], body=None)
    findings = engine.audit(req, checks=checks, insertion_kinds=(InsertionKind.QUERY_VALUE,))
    assert any(f.bug_class == "idor" and f.confirmed_by == OracleKind.ACHIEVED_STATE.value for f in findings)
