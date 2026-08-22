"""W13-5 (#498) — a nine-field-bound, single-use, owner-signed CAPABILITY TOKEN, validated at the executor
boundary so an authorization decision cannot be stale/replayed/reused for a different operation by the time
execution happens.

This file is import-clean (``vigil_core`` + stdlib only — no ``framework`` / ``strix`` / ``sigil``), so it
runs in the SOVEREIGN leg of the required `integration two-env boundary (P5)` CI job. It proves the token
machinery itself (unit) AND the STRUCTURAL invariant that the offense executor consults the capability
boundary before it runs a tool (pure AST over external_tool.py — no framework import needed). The FUNCTIONAL
end-to-end proof that ``run_external_tool`` refuses a bad token before launching a subprocess lives in
``test_executor_capability_boundary.py`` (offense leg — it imports ``framework``).

"FAILS WITHOUT THE FIX" (observed, not assumed): on a tree without W13-5 the module
``vigil_integration.live.capability_token`` does not exist, so this whole file ERRORs at collection
(ModuleNotFoundError). Observed on this tree by moving the module aside:

    $ mv integration/vigil_integration/live/capability_token.py /tmp/ ; \
      PYTHONPATH=integration:gateway .venv-sovereign/bin/python -m pytest -q \
        integration/tests/test_capability_token.py
    E   ModuleNotFoundError: No module named 'vigil_integration.live.capability_token'
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from vigil_core import generate_keypair
from vigil_integration.live.capability_token import (
    CapabilityAuthority,
    CapabilityGrant,
    CapabilityPolicy,
    CapabilityRefused,
    CapabilityToken,
    consume_capability_token,
    mint_capability_token,
    operation_hash,
    policy_digest,
    require_capability_token,
    verify_capability_token,
)
from vigil_integration.live.nonce_ledger import NonceLedger

_KP = generate_keypair()
_KEY_ID = "owner-root"
_AUTHORITY = CapabilityAuthority(owner_key_id=_KEY_ID, owner_public_key_b64=_KP.public_key_b64)
_POLICY_DIGEST = policy_digest({"warden": "A2", "charter": "alpha"})


def _grant(**over) -> CapabilityGrant:
    base = dict(
        deployment="deploy-prod-1",
        engagement="alpha",
        operation_hash=operation_hash("nmap", "127.0.0.1", ["nmap", "-p", "80", "127.0.0.1"]),
        target="127.0.0.1",
        tool="nmap",
        danger_class="recon",
        policy_digest=_POLICY_DIGEST,
    )
    base.update(over)
    return CapabilityGrant(**base)


def _mint(grant: CapabilityGrant, *, nonce: str = "n-0001", not_before: float = 1000.0,
          expiry: float = 1300.0) -> CapabilityToken:
    return mint_capability_token(
        grant, owner_private_key_b64=_KP.private_key_b64, key_id=_KEY_ID,
        nonce=nonce, not_before=not_before, expiry=expiry,
    )


def _ledger(tmp_path: Path) -> NonceLedger:
    return NonceLedger(tmp_path / "cap-nonces")


# ====================================================================================================
# The headline positive: a valid token authorizes EXACTLY once.
# ====================================================================================================
def test_a_valid_token_authorizes_exactly_once(tmp_path: Path):
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)

    # first presentation at the executor boundary → authorized, nonce burned.
    nonce = require_capability_token(token, grant, ledger=ledger, authority=_AUTHORITY, now=1100.0)
    assert nonce == "n-0001"

    # second presentation of the SAME token → refused (single-use spent).
    with pytest.raises(CapabilityRefused):
        require_capability_token(token, grant, ledger=ledger, authority=_AUTHORITY, now=1100.0)


# ====================================================================================================
# The four AC negative controls (each a SEPARATE assertion) — the gate is not a no-op.
# ====================================================================================================
def test_negative_control_replayed_token_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)
    assert consume_capability_token(token, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger).authorized
    replay = consume_capability_token(token, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not replay.authorized and "replay" in replay.reason.lower()


def test_negative_control_different_operation_hash_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)
    # the SAME tool+target but a DIFFERENT invocation (extra flag) → a different operation_hash.
    other = _grant(operation_hash=operation_hash("nmap", "127.0.0.1",
                                                 ["nmap", "-p", "80", "--script=vuln", "127.0.0.1"]))
    dec = consume_capability_token(token, other, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized and "operation_hash" in dec.reason
    # and it did NOT burn the nonce (the operation it WAS minted for can still run).
    assert not ledger.is_consumed(token.nonce)


def test_negative_control_token_past_expiry_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant, not_before=1000.0, expiry=1300.0)
    ledger = _ledger(tmp_path)
    dec = consume_capability_token(token, grant, authority=_AUTHORITY, now=1301.0, ledger=ledger)
    assert not dec.authorized and "window" in dec.reason.lower()
    assert not ledger.is_consumed(token.nonce)  # an expired token never burns the nonce


def test_negative_control_different_target_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)
    # isolate the TARGET field: keep operation_hash equal to the token's so the FIRST mismatch is `target`
    # (proving target is bound as its own field, independent of the operation_hash that also covers it).
    other = _grant(target="10.0.0.5")
    dec = consume_capability_token(token, other, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized and "target" in dec.reason
    assert not ledger.is_consumed(token.nonce)


# ====================================================================================================
# Every one of the nine bound fields is actually enforced (all nine, not just the four AC ones).
# ====================================================================================================
@pytest.mark.parametrize("field,bad", [
    ("deployment", "deploy-staging-9"),
    ("engagement", "bravo"),
    ("tool", "sqlmap"),
    ("danger_class", "exploit"),
    ("policy_digest", policy_digest({"warden": "A0"})),
])
def test_each_bound_operation_field_mismatch_is_refused(tmp_path: Path, field: str, bad: str):
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)
    dec = consume_capability_token(token, _grant(**{field: bad}),
                                   authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized and field in dec.reason
    assert not ledger.is_consumed(token.nonce)


def test_a_sleeper_window_beyond_max_lifetime_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant, not_before=1000.0, expiry=1000.0 + 10_000.0)  # >> 900s default
    ledger = _ledger(tmp_path)
    dec = consume_capability_token(token, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized and "lifetime" in dec.reason.lower()


def test_a_forged_signature_is_refused(tmp_path: Path):
    grant = _grant()
    token = _mint(grant)
    # tamper a bound field AFTER signing → the signature no longer covers the payload.
    forged = CapabilityToken(**{**token.__dict__, "danger_class": "exploit"})
    ledger = _ledger(tmp_path)
    # the binding mismatch OR the signature check refuses; either way it is not authorized, no burn.
    dec = consume_capability_token(forged, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized
    # a token whose signature we DIRECTLY break (keeping bindings intact) fails on the signature.
    broken_sig = CapabilityToken(**{**token.__dict__, "signature_b64": "AA" + token.signature_b64[2:]})
    dec2 = verify_capability_token(broken_sig, grant, authority=_AUTHORITY, now=1100.0,
                                   is_consumed=lambda _n: False)
    assert not dec2.authorized and "signature" in dec2.reason.lower()


def test_a_token_naming_a_non_owner_key_id_is_refused(tmp_path: Path):
    grant = _grant()
    # mint under a DIFFERENT key_id than the pinned deployment authority.
    token = mint_capability_token(grant, owner_private_key_b64=_KP.private_key_b64,
                                  key_id="worker-self", nonce="n-x", not_before=1000.0, expiry=1300.0)
    ledger = _ledger(tmp_path)
    dec = consume_capability_token(token, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger)
    assert not dec.authorized and "pinned owner key" in dec.reason


def test_an_invalid_token_never_griefs_a_victims_nonce(tmp_path: Path):
    """An invalid token (wrong target) must NOT burn its nonce — else an attacker could pre-spend a
    victim's nonce with a deliberately-broken token. Then the VALID token for that operation still works."""
    ledger = _ledger(tmp_path)
    good_grant = _grant()
    token = _mint(good_grant, nonce="shared-nonce")
    # present it against the WRONG operation first (refused, must not burn)
    wrong = _grant(target="10.0.0.5",
                   operation_hash=operation_hash("nmap", "10.0.0.5", ["nmap", "-p", "80", "10.0.0.5"]))
    assert not consume_capability_token(token, wrong, authority=_AUTHORITY, now=1100.0, ledger=ledger).authorized
    assert not ledger.is_consumed("shared-nonce")
    # now the correct presentation succeeds (nonce was preserved)
    assert consume_capability_token(token, good_grant, authority=_AUTHORITY, now=1100.0, ledger=ledger).authorized


# ====================================================================================================
# AC: the nonce ledger is the EXISTING O_EXCL one, not a new implementation.
# ====================================================================================================
def test_uses_the_existing_o_excl_nonce_ledger(tmp_path: Path):
    from vigil_integration.live import capability_token as ct
    from vigil_integration.live import nonce_ledger as nl
    # the module imports the SAME NonceLedger class (identity), not a re-implementation.
    assert ct.NonceLedger is nl.NonceLedger
    # and a successful consume creates the O_EXCL marker file that ledger keeps (proving reuse of it).
    grant = _grant()
    token = _mint(grant)
    ledger = _ledger(tmp_path)
    assert consume_capability_token(token, grant, authority=_AUTHORITY, now=1100.0, ledger=ledger).authorized
    markers = list((tmp_path / "cap-nonces").iterdir())
    assert len(markers) == 1 and re.fullmatch(r"[0-9a-f]{64}", markers[0].name)


def test_capability_token_module_imports_only_vigil_core_and_stdlib():
    """FATAL-2 / import-clean: the token module must never import framework/strix/sigil."""
    src = (Path(__file__).resolve().parents[1] / "vigil_integration" / "live" / "capability_token.py")
    tree = ast.parse(src.read_text(encoding="utf-8"))
    mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods.append(node.module or "")
    forbidden = [m for m in mods if m.split(".")[0] in {"framework", "strix", "sigil"}]
    assert not forbidden, f"capability_token imports offense/sovereign-only modules: {forbidden}"


# ====================================================================================================
# STRUCTURAL AC: no executor path runs a tool without the capability boundary being consulted first.
# Pure AST over external_tool.py — no framework import, so this runs in the sovereign leg too.
# ====================================================================================================
_EXTERNAL_TOOL = (
    Path(__file__).resolve().parents[1] / "vigil_integration" / "live" / "external_tool.py"
)
# the ONE call in run_external_tool that actually launches the target tool
_TARGET_EXEC = "backend.run(spec.build_argv(target)"
_BOUNDARY_CALL = "_capability_boundary_refusal("


def _fn_source(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(path.read_text(encoding="utf-8"), node) or ""
    raise AssertionError(f"function {name!r} not found in {path}")


def _boundary_dominates_exec(fn_src: str) -> bool:
    """True iff, in this function body, the capability-boundary call appears, precedes the target exec,
    AND a non-None boundary result returns before the exec (so exec is unreachable when the token is
    refused). This is the predicate the positive test asserts and the negative control refutes."""
    if _BOUNDARY_CALL not in fn_src or _TARGET_EXEC not in fn_src:
        return False
    b = fn_src.index(_BOUNDARY_CALL)
    x = fn_src.index(_TARGET_EXEC)
    if not b < x:
        return False
    # between the boundary call and the exec there must be a guard that RETURNS on refusal.
    between = fn_src[b:x]
    return ("is not None" in between) and ("return RunnerResult" in between)


def test_executor_consults_the_capability_boundary_before_running():
    fn_src = _fn_source(_EXTERNAL_TOOL, "run_external_tool")
    # there is exactly ONE target-exec site, and the boundary dominates it.
    assert fn_src.count(_TARGET_EXEC) == 1, "expected exactly one target-exec site in run_external_tool"
    assert _boundary_dominates_exec(fn_src), \
        "the capability boundary must be consulted (and refuse-return) before backend.run launches the tool"


def test_structural_check_is_not_a_no_op_negative_control():
    """The negative control for the structural test itself: a synthetic executor that runs the tool WITHOUT
    the boundary guard must be REJECTED by the same predicate — so the positive test above cannot pass
    vacuously."""
    bad = (
        "def run_external_tool(spec, target, *, backend):\n"
        "    outcome = backend.run(spec.build_argv(target), timeout=1)\n"
        "    return outcome\n"
    )
    assert not _boundary_dominates_exec(bad)
    # and a version that calls the boundary but does NOT return on refusal (falls through to exec) is also
    # rejected — the guard must actually stop execution.
    no_return = (
        "def run_external_tool(spec, target, *, backend, capability):\n"
        "    _capability_boundary_refusal(capability, spec, target, 'x')\n"
        "    outcome = backend.run(spec.build_argv(target), timeout=1)\n"
        "    return outcome\n"
    )
    assert not _boundary_dominates_exec(no_return)
