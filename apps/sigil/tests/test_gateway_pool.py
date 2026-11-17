"""PRICING G1 — the provider-account POOL spec (``vigil_core.model_metering.gateway_pool_spec``) and its key
resolution (``sigil.provider_key.pool_accounts``). Tests use FAKE keys only."""
from __future__ import annotations

import json

import pytest

from vigil_core import model_metering as mm
from sigil import provider_key as pk


def _env(accounts, **keys):
    e = {"VIGIL_GATEWAY_POOL": json.dumps(accounts)}
    e.update(keys)
    return e


def test_an_unset_pool_is_empty():
    assert mm.gateway_pool_spec({}) == []
    assert pk.pool_accounts({}) == []


def test_a_valid_pool_spec_is_parsed_and_keys_resolve():
    e = _env([{"id": "ws-a", "key_env": "KEY_A", "workspace_id": "wrk_a"},
              {"id": "ws-b", "key_env": "KEY_B"}],
             KEY_A="sk-fake-a", KEY_B="sk-fake-b")
    spec = mm.gateway_pool_spec(e)
    assert [a["id"] for a in spec] == ["ws-a", "ws-b"] and spec[0]["kind"] == "anthropic"
    accounts = pk.pool_accounts(e)
    assert accounts[0] == {"id": "ws-a", "key": "sk-fake-a", "workspace_id": "wrk_a", "upstream": "", "kind": "anthropic"}
    assert accounts[1]["key"] == "sk-fake-b"


@pytest.mark.parametrize("bad", [
    "not json",
    "{}",                                                   # not an array
    "[]",                                                   # empty
    json.dumps([{"key_env": "K"}]),                         # no id
    json.dumps([{"id": "a", "key_env": "K"}, {"id": "a", "key_env": "K2"}]),  # duplicate id
    json.dumps([{"id": "a", "key_env": "bad name"}]),       # key_env is not an env-var name
    json.dumps([{"id": "a"}]),                              # no key_env
])
def test_a_malformed_pool_spec_is_refused(bad):
    with pytest.raises(mm.MeteringError):
        mm.gateway_pool_spec({"VIGIL_GATEWAY_POOL": bad})


def test_a_second_cloud_kind_is_refused_at_the_interface():
    with pytest.raises(mm.MeteringError) as exc:
        mm.gateway_pool_spec(_env([{"id": "bedrock", "key_env": "K", "kind": "bedrock"}], K="x"))
    assert "overflow" in str(exc.value) or "not wired" in str(exc.value)


def test_a_pool_account_with_no_key_is_refused_fail_closed():
    e = _env([{"id": "a", "key_env": "KEY_A"}])           # KEY_A unset
    with pytest.raises(pk.ProviderKeyError):
        pk.pool_accounts(e)
