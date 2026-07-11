"""Tests for memory.embed default selection + byte-identity (WS-G).

Contract:
  * the deterministic LexicalEmbedder is the DEFAULT (env unset) — even where
    sentence-transformers is installed, the default/replayed path stays
    deterministic;
  * semantic is opt-in by name and raises loudly when absent;
  * the optional numpy fast path in the embedder is byte-identical to the
    pure-Python path.
"""

from __future__ import annotations

import pytest

from framework.v2.common import capabilities as cap
from framework.v2.memory import embed


@pytest.fixture(autouse=True)
def _reset_embedder_cache() -> None:
    embed.reset_cache()
    yield
    embed.reset_cache()


def test_default_is_lexical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_EMBEDDER", raising=False)
    e = embed.get_embedder()
    assert isinstance(e, embed.LexicalEmbedder)
    assert e.name == "lexical-256" and e.dim == 256


def test_explicit_lexical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "lexical")
    assert isinstance(embed.get_embedder(), embed.LexicalEmbedder)


def test_unknown_value_degrades_to_lexical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "wat")
    assert isinstance(embed.get_embedder(), embed.LexicalEmbedder)


@pytest.mark.skipif(cap.has_semantic(), reason="sentence-transformers installed — absence path only")
@pytest.mark.parametrize("val", ["sentence-transformers", "st", "semantic"])
def test_semantic_opt_in_raises_when_absent(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", val)
    with pytest.raises(ImportError):
        embed.get_embedder()


@pytest.mark.skipif(cap.has_semantic(), reason="sentence-transformers installed — absence path only")
def test_auto_falls_back_to_lexical_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CRUCIBLE_EMBEDDER", "auto")
    assert isinstance(embed.get_embedder(), embed.LexicalEmbedder)


def test_lexical_is_deterministic() -> None:
    a = embed.LexicalEmbedder().embed("path traversal ../../etc/passwd ssrf metadata")
    b = embed.LexicalEmbedder().embed("path traversal ../../etc/passwd ssrf metadata")
    assert a == b


def test_embed_fast_path_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "SQL injection in the login form param id=1 OR 1=1 -- duplicate duplicate"
    monkeypatch.delenv("CRUCIBLE_FAST_NUMERICS", raising=False)
    off = embed.LexicalEmbedder().embed(text)
    monkeypatch.setenv("CRUCIBLE_FAST_NUMERICS", "1")
    on = embed.LexicalEmbedder().embed(text)
    assert off == on


def test_empty_and_stopword_only_text() -> None:
    e = embed.LexicalEmbedder()
    assert e.embed("") == [0.0] * e.dim
    # stopword-only text tokenizes to nothing → zero vector
    assert e.embed("the a an and or") == [0.0] * e.dim
