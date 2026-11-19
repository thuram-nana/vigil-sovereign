"""Consumer PR-F — the config flag + shard topology reader (``config.customer_fair_queue_enabled`` /
``config.shard_ids``). Default-OFF and fail-safe, mirroring ``redpen_enabled`` / ``multi_shard_enabled``."""
from __future__ import annotations

import pytest

from sigil import config


def test_fair_queue_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_FAIR_QUEUE", raising=False)
    assert config.customer_fair_queue_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "enabled", "TRUE", " On "])
def test_fair_queue_flag_on_for_affirmatives(monkeypatch, val):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", val)
    assert config.customer_fair_queue_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "maybe", "2"])
def test_fair_queue_flag_off_for_non_affirmatives(monkeypatch, val):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", val)
    assert config.customer_fair_queue_enabled() is False


def test_shard_ids_default_empty(monkeypatch):
    monkeypatch.delenv("VIGIL_SHARD_IDS", raising=False)
    assert config.shard_ids() == ()


def test_shard_ids_parses_and_dedups(monkeypatch):
    monkeypatch.setenv("VIGIL_SHARD_IDS", " shard01 , shard02 ,shard01, shard03 ")
    assert config.shard_ids() == ("shard01", "shard02", "shard03")  # trimmed, de-duplicated, order preserved


def test_shard_ids_drops_malformed_components(monkeypatch):
    # path-traversal / separators / absolute / space / non-alnum-start are DROPPED, never reach the signer.
    # (a NUL is unrepresentable in a real env var — the OS rejects it — and is also outside the regex class.)
    monkeypatch.setenv("VIGIL_SHARD_IDS", "ok1,../evil,a/b,/abs,with space,ok2,.hidden")
    assert config.shard_ids() == ("ok1", "ok2")


def test_shard_ids_all_malformed_is_empty(monkeypatch):
    monkeypatch.setenv("VIGIL_SHARD_IDS", "../a,/b, , ")
    assert config.shard_ids() == ()
