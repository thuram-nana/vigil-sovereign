"""vigil_core.posture — the shared VIGIL_POSTURE / legacy-owner-token parse both trust planes read.

The load-bearing property (W10-7): the offense refuse-to-start gate and the sovereign server must agree,
byte-for-byte, on (a) whether the production posture is armed and (b) whether the legacy shared owner token
may resolve to owner. These tests pin that parse against an explicit env mapping (no process env mutated).
"""
from __future__ import annotations

import pytest

from vigil_core.posture import (
    CUSTOMER_PROD_EXECUTION_ENV,
    GOVERNED_ENV,
    LEGACY_OWNER_TOKEN_ENV,
    POSTURE_ENV,
    customer_prod_execution_enabled,
    is_governed_posture,
    is_production_posture,
    legacy_owner_token_disabled,
    legacy_owner_token_grants_owner,
    production_posture,
)


@pytest.mark.parametrize("val,hit", [
    ("production", True), ("prod", True), ("Prod", True), ("PRODUCTION", True), ("  production  ", True),
    ("", False), ("dev", False), ("staging", False), ("prod1", False),
])
def test_production_posture_parse_is_case_and_whitespace_robust(val, hit):
    env = {POSTURE_ENV: val}
    assert (production_posture(env) is not None) is hit
    assert is_production_posture(env) is hit
    if hit:
        assert production_posture(env) == val.strip()        # returns the RAW (trimmed) value


def test_production_posture_absent_env_is_not_armed():
    assert production_posture({}) is None and is_production_posture({}) is False


@pytest.mark.parametrize("val,disabled", [
    ("0", True), ("off", True), ("false", True), ("no", True), ("disabled", True), ("OFF", True),
    ("", False), ("1", False), ("true", False), ("yes", False),
])
def test_legacy_token_disabled_only_on_explicit_falsy(val, disabled):
    assert legacy_owner_token_disabled({LEGACY_OWNER_TOKEN_ENV: val}) is disabled


def test_legacy_token_absent_env_is_enabled_by_default():
    assert legacy_owner_token_disabled({}) is False          # unset ⇒ the fail-open dev convenience


def test_grants_owner_is_the_conjunction_not_production_and_not_disabled():
    # the truth table the server keys on: owner ONLY when NOT production AND NOT explicitly disabled.
    assert legacy_owner_token_grants_owner({}) is True                                   # default dev
    assert legacy_owner_token_grants_owner({POSTURE_ENV: "production"}) is False         # W10-7 fail-closed
    assert legacy_owner_token_grants_owner({POSTURE_ENV: "prod"}) is False
    assert legacy_owner_token_grants_owner({LEGACY_OWNER_TOKEN_ENV: "0"}) is False       # explicit opt-out
    # production wins even if the toggle is left ON — the posture refusal is unconditional.
    assert legacy_owner_token_grants_owner({POSTURE_ENV: "production",
                                            LEGACY_OWNER_TOKEN_ENV: "1"}) is False
    assert legacy_owner_token_grants_owner({POSTURE_ENV: "dev"}) is True   # a non-production posture value


def test_governed_posture_refuses_the_legacy_owner_token_without_the_egress_lockdown():
    """Phase 0.2 / R-CRITICAL-2: a GOVERNED deployment (VIGIL_GOVERNED truthy) refuses the fail-open owner
    token — requiring per-user PoP auth — WITHOUT arming production's loopback-only egress lockdown, so an
    authorized external engagement can still run. Default (unset) is unchanged, so a dev / single-owner host
    is never silently locked out."""
    assert is_governed_posture({}) is False                                  # default: not governed
    assert is_governed_posture({GOVERNED_ENV: "1"}) is True
    assert is_governed_posture({GOVERNED_ENV: "true"}) is True
    assert is_governed_posture({GOVERNED_ENV: "0"}) is False                  # a falsy value ⇒ not governed
    assert is_governed_posture({GOVERNED_ENV: ""}) is False
    # governed refuses the token even with the toggle left ON (unconditional, like production)...
    assert legacy_owner_token_grants_owner({GOVERNED_ENV: "1"}) is False
    assert legacy_owner_token_grants_owner({GOVERNED_ENV: "1", LEGACY_OWNER_TOKEN_ENV: "1"}) is False
    # ...but governed does NOT arm the production posture, so external egress is not forced off (decoupled).
    assert is_production_posture({GOVERNED_ENV: "1"}) is False


def test_customer_prod_execution_is_disabled_by_default_and_needs_an_explicit_optin():
    # K4: production-target customer execution is DISABLED unless explicitly opted in (fail-closed).
    assert customer_prod_execution_enabled({}) is False                       # unset ⇒ disabled
    assert customer_prod_execution_enabled({CUSTOMER_PROD_EXECUTION_ENV: ""}) is False
    for truthy in ("1", "on", "true", "yes", "enabled", "TRUE", "  on  "):
        assert customer_prod_execution_enabled({CUSTOMER_PROD_EXECUTION_ENV: truthy}) is True
    for falsy in ("0", "off", "false", "no", "disabled", "maybe", "2", "prod"):
        assert customer_prod_execution_enabled({CUSTOMER_PROD_EXECUTION_ENV: falsy}) is False
    # DECOUPLED from VIGIL_POSTURE: arming production does NOT enable customer prod execution (and vice-versa).
    assert customer_prod_execution_enabled({POSTURE_ENV: "production"}) is False
