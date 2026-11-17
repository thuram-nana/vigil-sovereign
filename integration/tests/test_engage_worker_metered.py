"""M1c-2b — the customer-launch WORKER drives a metered run through the model gateway with its grant.

Pins the money-critical + FATAL-2 contract of ``make_engage_worker`` under METERED billing:
  * a METERED run (a model grant published for this launch) is wrapped in ``_model_grant_scope``: every model
    env var points the engine at the loopback gateway with the grant, routing is OFF, and NO provider key is in
    the environment — restored EXACTLY on exit;
  * a metered launch with NO usable grant (a grant file present but malformed / for another nonce) is REFUSED
    BEFORE the arm, so the single-use floor is never burned;
  * the gateway's terminal credit stop (``CreditsExhausted``) is a clean CREDIT PAUSE: the worker emits NO
    completion signal (no COMPLETED charge, no FAILED refund — the lease is HELD for a W3 top-up + resume),
    rolls the attempt slot back + records resume-required (so a resume re-arms without re-burning the floor), and
    RETURNS the distinct ``paused_credit`` outcome (no re-drive);
  * DEFAULT-OFF: a FLAT launch (no grant) is byte-identical — ``os.environ`` is untouched and the run settles
    exactly as before.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the CreditsExhausted branch (a credit stop falls into the FAILED path) -> test_credit_stop_is_a_pause_not_a_settle
  * worker stops forcing routing OFF for a metered run                          -> test_a_metered_run_scopes_the_gateway_env_and_routing_off
  * _model_grant_scope stops unsetting the provider key                         -> test_the_grant_scope_unsets_the_provider_key_and_restores_exactly
  * _read_run_model_grant stops refusing a metered-but-unusable grant           -> test_a_metered_launch_with_no_usable_grant_is_refused_before_the_arm
  * the grant model/effort are not scoped from the decoded grant                -> test_a_metered_run_scopes_the_gateway_env_and_routing_off
"""
from __future__ import annotations

import datetime as _dt
import os
import tempfile
from datetime import timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_core.model_grant import ModelGrant, encode_token
from vigil_integration.jobs.engage_worker import (
    _ATTEMPTS_DIRNAME, _GRANT_SCOPE_UNSET, _RESUME_MARK_SUFFIX, _attempt_key, _model_grant_scope,
    _read_run_model_grant, CreditPaused, PAUSED_CREDIT_OUTCOME, make_engage_worker,
)
from vigil_integration.jobs.launch_trigger import launch_delivery_id
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.credit_lease_broker import write_credit_lease
from vigil_integration.live.model_grant_broker import grant_path, read_model_grant, write_model_grant

# The worker imports framework LAZILY; skip cleanly in the sovereign leg (it runs in the offense/integration leg).
pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in the sovereign leg")
from framework.v2.common.errors import CreditsExhausted  # noqa: E402 — after importorskip, by design

SLUG, HOST, ORG = "cust_m1c2b", "apme.cm", "org_a"
GATEWAY = "http://127.0.0.1:8742"
MODEL = "claude-opus-4-8"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, nonce="n1", issued=1000.0, units=10):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=ORG, scope_host=HOST, units_reserved=units,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _grant_token(owner, *, nonce="n1", model=MODEL, effort="xhigh", issued=1000.0):
    g = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=SLUG, nonce=nonce, model=model,
                   effort=effort, cap_nano_usd=1_000_000, not_after=issued + 3600.0, issued_at=issued)
    return encode_token(g, owner.private_key_b64)


def _authority(slug, scope, *, env="twin", now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)
    return EngagementAuthority(engagement_slug=slug, environment=env, scope=scope, issued_by="customer:org_a",
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _rig(monkeypatch, owner):
    from framework.v2.authority import store as authz_store
    base = tempfile.mkdtemp()
    write_credit_lease(base, SLUG, _lease(owner), _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _authority(slug, [HOST]))
    return base


def _job(*, nonce="n1"):
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id=ORG, commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce, "org_id": ORG})


def _mk(monkeypatch, base, owner, run, emits):
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal",
                        lambda **kw: emits.append(kw["outcome"]))
    # the REAL owner trust root (not object()) so the worker can DECODE the grant for its model/effort.
    return make_engage_worker(trust_root=_owner_root(owner), base_dir=base, run=run, signers=[("k", "v")])


def _slot(base, nonce, n):
    return os.path.join(base, _ATTEMPTS_DIRNAME, f"{_attempt_key(SLUG, nonce)}.{n}.json")


def _resume_marker(base, nonce):
    return os.path.join(base, _ATTEMPTS_DIRNAME, f"{_attempt_key(SLUG, nonce)}.{_RESUME_MARK_SUFFIX}.json")


# --------------------------------------------------------------------------------------- the grant scope (unit)
def test_the_grant_scope_sets_the_gateway_env_and_unsets_the_provider_key(monkeypatch):
    # a stale provider key + hot-reload flag + a sibling api-base in the ambient env
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-owner-secret")
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://evil:9")
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)

    class _B:
        token = "vmg1.grant-one"
        gateway_url = GATEWAY

    with _model_grant_scope(_B(), MODEL, "xhigh"):
        assert os.environ["ANTHROPIC_BASE_URL"] == GATEWAY
        assert os.environ["ANTHROPIC_API_KEY"] == "vmg1.grant-one"
        assert os.environ["VIGIL_MODEL_GRANT"] == "vmg1.grant-one"
        assert os.environ["CRUCIBLE_LLM_BACKEND"] == "anthropic"
        assert os.environ["CRUCIBLE_MODEL_ROUTING"] == "0"
        assert os.environ["CRUCIBLE_ANTHROPIC_MODEL"] == MODEL
        assert os.environ["CRUCIBLE_EFFORT"] == "xhigh"
        assert os.environ["STRIX_LLM"] == f"anthropic/{MODEL}"
        assert os.environ["LLM_API_BASE"] == GATEWAY
        assert os.environ["LLM_API_KEY"] == "vmg1.grant-one"
        # the provider key + its hot-reload + the api-base siblings are UNSET for the whole run
        for k in _GRANT_SCOPE_UNSET:
            assert k not in os.environ, k


def test_the_grant_scope_restores_exactly_including_unset(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)           # was UNSET
    monkeypatch.setenv("CRUCIBLE_MODEL_ROUTING", "1")                 # had a prior value
    monkeypatch.setenv("SIGIL_ANTHROPIC_API_KEY", "sk-prior")         # a provider key the scope must restore after

    class _B:
        token = "t"
        gateway_url = GATEWAY

    with _model_grant_scope(_B(), MODEL, "high"):
        pass
    assert "ANTHROPIC_BASE_URL" not in os.environ                     # back to UNSET
    assert os.environ["CRUCIBLE_MODEL_ROUTING"] == "1"               # back to its prior value
    assert os.environ["SIGIL_ANTHROPIC_API_KEY"] == "sk-prior"        # restored after the run


def test_the_grant_scope_is_a_no_op_when_flat(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-flat")
    before = dict(os.environ)
    with _model_grant_scope(None, "", ""):                           # flat (no bundle) ⇒ byte-identical
        assert os.environ.get("VIGIL_MODEL_GRANT") is None
        assert os.environ["ANTHROPIC_API_KEY"] == "sk-flat"          # untouched
    assert dict(os.environ) == before


# --------------------------------------------------------------------------------------- the worker (metered)
def test_a_metered_run_scopes_the_gateway_env_and_routing_off(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    write_model_grant(base, SLUG, "n1", _grant_token(owner), GATEWAY)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-provider")           # a provider key the metered run must NOT see
    emits: list = []
    seen: dict = {}

    def _run(**kw):
        seen["base"] = os.environ.get("ANTHROPIC_BASE_URL")
        seen["grant"] = os.environ.get("VIGIL_MODEL_GRANT")
        seen["key"] = os.environ.get("ANTHROPIC_API_KEY")
        seen["model"] = os.environ.get("CRUCIBLE_ANTHROPIC_MODEL")
        seen["effort"] = os.environ.get("CRUCIBLE_EFFORT")
        seen["routing"] = os.environ.get("CRUCIBLE_MODEL_ROUTING")
        seen["strix"] = os.environ.get("STRIX_LLM")
        return {"facts": 0}

    w = _mk(monkeypatch, base, owner, _run, emits)
    w(_job(nonce="n1"))
    assert seen["base"] == GATEWAY
    assert seen["grant"] and seen["grant"].startswith("vmg1.")
    assert seen["key"] == seen["grant"]                              # the grant is the key, NEVER the provider key
    assert seen["model"] == MODEL                                    # from the DECODED grant, not VIGIL_RUN_MODEL
    assert seen["effort"] == "xhigh"                                 # from the decoded grant
    assert seen["routing"] == "0"                                    # a metered run never routes
    assert seen["strix"] == f"anthropic/{MODEL}"
    assert emits == ["completed"]                                    # a metered success still settles
    # restored on exit: the ambient provider key is back, the grant env is gone
    assert os.environ.get("VIGIL_MODEL_GRANT") is None
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-provider"


def test_credit_stop_is_a_pause_not_a_settle(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    write_model_grant(base, SLUG, "n1", _grant_token(owner), GATEWAY)
    emits: list = []

    def _run(**kw):
        raise CreditsExhausted("the model gateway stopped this run: credits exhausted")

    w = _mk(monkeypatch, base, owner, _run, emits)
    out = w(_job(nonce="n1"))
    assert isinstance(out, CreditPaused) and out.outcome == PAUSED_CREDIT_OUTCOME   # the distinct parked outcome
    assert out.engagement_slug == SLUG and out.nonce == "n1"
    assert emits == []                                              # NO settle — not COMPLETED (charge), not FAILED (refund)
    assert not os.path.exists(_slot(base, "n1", 1))                 # the attempt slot was rolled back (no crash budget)
    assert os.path.exists(_resume_marker(base, "n1"))              # resume-required recorded (W3 resumes without re-burning)


def test_credit_stop_does_not_re_drive(monkeypatch):
    # A credit pause RETURNS (never raises): JobRunner keeps the one-shot delivery, so the launch is PARKED and
    # does not re-drive into the still-exhausted gateway (unlike EngagementPaused, which re-raises to re-enqueue).
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    write_model_grant(base, SLUG, "n1", _grant_token(owner), GATEWAY)

    def _run(**kw):
        raise CreditsExhausted("credits exhausted")

    w = _mk(monkeypatch, base, owner, _run, [])
    out = w(_job(nonce="n1"))                                       # returns — does NOT raise
    assert isinstance(out, CreditPaused)


def test_a_metered_launch_with_no_usable_grant_is_refused_before_the_arm(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    # a grant FILE present for this slug but bound to a DIFFERENT nonce ⇒ unusable for this launch (metered, no
    # model access) ⇒ the worker refuses BEFORE the arm so the single-use floor is never burned.
    write_model_grant(base, SLUG, "other-nonce", _grant_token(owner, nonce="other-nonce"), GATEWAY)
    armed: list = []

    def _run(**kw):
        armed.append(True)
        return {"facts": 0}

    w = _mk(monkeypatch, base, owner, _run, [])
    with pytest.raises(RuntimeError, match="BEFORE the arm"):
        w(_job(nonce="n1"))
    assert armed == []                                             # the runner (the arm) was never reached


def test_a_grant_that_does_not_verify_is_refused_before_the_arm(monkeypatch):
    owner = generate_keypair()
    other = generate_keypair()                                    # a DIFFERENT key signs the grant
    base = _rig(monkeypatch, owner)
    write_model_grant(base, SLUG, "n1", _grant_token(other), GATEWAY)   # does not verify under the owner root
    armed: list = []

    def _run(**kw):
        armed.append(True)
        return {"facts": 0}

    w = _mk(monkeypatch, base, owner, _run, [])
    with pytest.raises(RuntimeError, match="does not verify under the owner key"):
        w(_job(nonce="n1"))
    assert armed == []


# --------------------------------------------------------------------------------------- byte-identical (flat)
def test_a_flat_launch_is_byte_identical(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)                                # NO model grant written ⇒ a flat launch
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-flat")
    emits: list = []
    seen: dict = {}

    def _run(**kw):
        seen["grant"] = os.environ.get("VIGIL_MODEL_GRANT")
        seen["base"] = os.environ.get("ANTHROPIC_BASE_URL")
        seen["key"] = os.environ.get("ANTHROPIC_API_KEY")
        return {"facts": 0}

    w = _mk(monkeypatch, base, owner, _run, emits)
    w(_job(nonce="n1"))
    assert seen["grant"] is None                                   # no grant scoped
    assert seen["base"] is None                                    # no gateway
    assert seen["key"] == "sk-flat"                                # the run's key env is untouched
    assert emits == ["completed"]                                  # settles exactly as a flat launch always has
    assert read_model_grant(base, SLUG, expect_nonce="n1") is None # nothing minted a grant
    assert grant_path(base, SLUG) is not None and not os.path.exists(grant_path(base, SLUG))


def test_read_run_model_grant_flat_is_none(monkeypatch):
    owner = generate_keypair()
    base = tempfile.mkdtemp()
    bundle, model, effort = _read_run_model_grant(base, SLUG, "n1", _owner_root(owner))
    assert bundle is None and model == "" and effort == ""         # no grant file ⇒ flat (byte-identical)


def test_read_run_model_grant_decodes_a_valid_grant(monkeypatch):
    owner = generate_keypair()
    base = tempfile.mkdtemp()
    write_model_grant(base, SLUG, "n1", _grant_token(owner, model=MODEL, effort="xhigh"), GATEWAY)
    bundle, model, effort = _read_run_model_grant(base, SLUG, "n1", _owner_root(owner))
    assert bundle is not None and model == MODEL and effort == "xhigh"
