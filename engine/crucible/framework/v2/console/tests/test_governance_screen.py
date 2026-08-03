"""
Console Governance & Gate audit provider (UI flagship wave, slice 3) — READ/AUDIT-ONLY.

These assert the safety + honesty properties the screen stakes its credibility on:
  * the provider returns the read-only posture shape (governed/sovereignty/entitlement/gate/destruction);
  * GOVERNED is fail-honest — True ONLY when capability entitlement is actually enforced;
  * an un-provisioned destruction quorum is honestly present:False, never a fabricated "secure" quorum;
  * the read is side-effect-free (idempotent) — a governance READ never mutates state;
  * FATAL-2 + no-mint: the offense-plane provider imports NO vigil_integration gate mint module and
    exposes no provision/authorize/consume path — it reads persisted public files with stdlib + vigil_core.
"""

from __future__ import annotations

import inspect
import re

from framework.v2.console import api


def test_governance_data_is_read_only_posture_shape() -> None:
    d = api.governance_data()
    assert d["read_only"] is True
    assert {"governed", "sovereignty", "entitlement", "gate", "destruction", "note"} <= set(d)
    conjuncts = d["gate"]["conjuncts"]
    # the safety-gate conjuncts every target-touching action must clear are surfaced for audit
    assert "authority/kill-switch" in conjuncts
    assert "destructive-confirm" in conjuncts


def test_governed_is_fail_honest() -> None:
    """GOVERNED is True ONLY when entitlement is actually enforced; anything else is UNGOVERNED."""
    d = api.governance_data()
    ent = d.get("entitlement") or {}
    assert d["governed"] == bool(ent.get("enforced"))


def test_destruction_absent_is_honest_not_faked() -> None:
    """An un-provisioned quorum is present:False with an honest reason — never a fabricated 0-pending 'secure'."""
    des = api.governance_data()["destruction"]
    if des.get("present") is False:
        assert des.get("note")  # an honest 'no quorum provisioned' reason
    else:
        tr = des.get("trust_root") or {}
        assert "threshold" in tr and "authorizer_ids" in tr  # only public audit fields


def test_governance_read_is_side_effect_free() -> None:
    """A governance READ must not mutate state: two calls agree (idempotent)."""
    a = api.governance_data()
    b = api.governance_data()
    assert a["governed"] == b["governed"]
    assert (a["destruction"] or {}).get("present") == (b["destruction"] or {}).get("present")


def test_provider_imports_no_gate_mint_module() -> None:
    """FATAL-2 + safety: the offense-console governance provider must NOT import a vigil_integration gate
    mint module. Reads persisted files with stdlib + vigil_core only. (Checks import lines, so a comment
    that merely NAMES a module for reference does not trip it.)"""
    src = inspect.getsource(api._destruction_audit) + "\n" + inspect.getsource(api.governance_data)
    import_lines = "\n".join(ln for ln in src.splitlines() if re.match(r"\s*(from|import)\s", ln))
    for forbidden in ("vigil_integration", "destruction_gate", "destruction_provision", "nonce_ledger"):
        assert forbidden not in import_lines, f"governance provider IMPORTS a gate mint module: {forbidden}"


def test_provider_exposes_no_mint_or_authorize_call() -> None:
    """No destructive mint/authorize/consume verb is invoked anywhere in the read path."""
    src = inspect.getsource(api._destruction_audit) + "\n" + inspect.getsource(api.governance_data)
    for verb in ("consume_authorization", "sign_authorization", "authorize_destruction",
                 "generate_authority", "try_consume", "write_trust_root", "provision_destruction"):
        assert verb + "(" not in src, f"governance provider CALLS a mint/authorize verb: {verb}"
