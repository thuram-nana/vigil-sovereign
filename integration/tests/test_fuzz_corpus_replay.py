"""Fast, deterministic, REQUIRED stand-in for coverage-guided fuzzing (W11-3, issue #484).

atheris cannot run on an ordinary PR runner (native libFuzzer instrumentation, and it is not installed),
so the SLOW coverage-guided fuzz over the three parser families is a SCHEDULED job
(.github/workflows/mutation-fuzz.yml). What runs on EVERY PR is this: replay each harness's COMMITTED
seed corpus through its ``TestOneInput`` (proving totality — the parser never crashes on the seeds) and,
for each family, a NEGATIVE CONTROL proving the parser/verifier actually has teeth (it is not a no-op
that accepts everything / detects nothing).

Two-env boundary: the JSON and spine harnesses need only ``vigil_core`` (the offense-free substrate) and
run in BOTH CI legs. The HTTP harness targets ``framework.v2.aegis.inspect`` (the offense engine), so its
test is gated behind ``pytest.importorskip("framework...")`` — it SKIPS in the sovereign leg and RUNS in
the offense leg. Because of that importorskip, this file is listed explicitly in the offense leg of
.github/workflows/ci.yml (enforced by test_ci_framework_tests_run_in_offense_leg.py).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

_REPO = Path(__file__).resolve().parents[2]
_HARNESS_DIR = _REPO / "tools" / "fuzz" / "atheris"
_CORPUS = _HARNESS_DIR / "corpus"


def _load_harness(name: str) -> ModuleType:
    """Import a fuzz harness module by file path (its target imports run at load time)."""
    spec = importlib.util.spec_from_file_location(f"_harness_{name}", _HARNESS_DIR / f"{name}.py")
    assert spec and spec.loader, f"cannot load harness {name}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _seeds(family: str) -> list[bytes]:
    d = _CORPUS / family
    return [p.read_bytes() for p in sorted(d.iterdir()) if p.is_file()]


def _replay(harness: ModuleType, family: str) -> int:
    seeds = _seeds(family)
    assert seeds, f"the {family} seed corpus must be committed and non-empty"
    for i, seed in enumerate(seeds):
        try:
            harness.TestOneInput(seed)
        except Exception as exc:  # noqa: BLE001 — a raise on a seed is exactly the finding we test for.
            raise AssertionError(f"{family} harness crashed on committed seed #{i}: {exc!r}") from exc
    return len(seeds)


# --------------------------------------------------------------------------------------------------
# Committed-corpus guardrail (the AC's "a corpus committed").
# --------------------------------------------------------------------------------------------------
def test_every_family_has_a_committed_corpus():
    for family in ("json", "spine", "http"):
        assert (_CORPUS / family).is_dir(), f"missing committed corpus dir for {family}"
        assert _seeds(family), f"the {family} corpus is empty"


# --------------------------------------------------------------------------------------------------
# JSON canonicalisation family.
# --------------------------------------------------------------------------------------------------
def test_json_harness_replays_committed_corpus_without_crashing():
    assert _replay(_load_harness("fuzz_json"), "json") >= 5


def test_json_canonicalisation_negative_controls():
    """Teeth: canonicalisation is order-independent AND value-sensitive (a no-op/constant canonicaliser
    would fail one of these), and a malformed JSON seed is REJECTED (not silently accepted)."""
    from vigil_core.canonical import canonical_json

    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1}), "must be order-independent"
    assert canonical_json({"a": 1}) != canonical_json({"a": 2}), "must distinguish different values"
    with pytest.raises(json.JSONDecodeError):
        json.loads("{bad json")  # the parse the harness relies on genuinely rejects malformed input


# --------------------------------------------------------------------------------------------------
# Spine-record family.
# --------------------------------------------------------------------------------------------------
def test_spine_harness_replays_committed_corpus_without_crashing():
    assert _replay(_load_harness("fuzz_spine"), "spine") >= 5


def test_spine_verifier_detects_tampering_negative_control():
    """Teeth: a validly built chain verifies, but a deleted-middle or edited entry MUST verify False —
    a no-op verifier that always returned True would fail this."""
    from vigil_core import build_chain, verify_chain
    from vigil_core.canonical import sha256_hex

    chain = build_chain([sha256_hex(str(i).encode()) for i in range(5)])
    ok, _ = verify_chain(chain)
    assert ok, "a validly built chain must verify"

    deleted = chain[:2] + chain[3:]
    assert not verify_chain(deleted)[0], "deleting a middle entry MUST be detected"

    edited = [e.model_copy() for e in chain]
    edited[2] = edited[2].model_copy(update={"cert_digest": "deadbeef"})
    assert not verify_chain(edited)[0], "editing an entry MUST be detected"


# --------------------------------------------------------------------------------------------------
# HTTP request family (offense engine — offense leg only).
# --------------------------------------------------------------------------------------------------
def test_http_harness_replays_committed_corpus_without_crashing():
    pytest.importorskip("framework.v2.aegis.inspect")
    assert _replay(_load_harness("fuzz_http"), "http") >= 5


def test_http_inspector_has_teeth_negative_control():
    """Teeth: a benign request produces NO confirmed block, while a structured SQLi request produces a
    CONFIRMED verdict carrying a re-runnable certificate. A no-op inspector (always None, or always
    confirmed) would fail one of these."""
    inspect = pytest.importorskip("framework.v2.aegis.inspect")
    from urllib.parse import quote

    benign = inspect.inspect_request("GET", "/search?q=" + quote("hello world"), [], None)
    assert benign is None or benign.decision != "confirmed", "benign input must not be a confirmed block"

    sqli = inspect.inspect_request("GET", "/search?q=" + quote("' OR '1'='1"), [], None)
    assert sqli is not None and sqli.decision == "confirmed" and sqli.attack_class == "sqli_attempt", (
        "a structured SQLi attempt must be a confirmed sqli verdict"
    )
    assert sqli.certificate is not None, "a confirmed verdict must carry a re-runnable certificate"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
