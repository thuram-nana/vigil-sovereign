"""DATA-GROUND-TRUTH.md is generated from one code-grounded source, and cannot rot (W14-3 #505).

WHY THIS TEST EXISTS. ``DATA-GROUND-TRUTH.md`` is the data-at-rest / egress declaration a reviewer
reads first. Nothing kept it true of the code, and it had already been contradicted once by a moved
key path (W0-4 #399). It is now rendered from ``docs/data-ground-truth/data-stores.json`` by
``docs/data-ground-truth/gen_data_ground_truth.py``, and that source is GROUNDED against the code that
performs each egress: every cited symbol/env-override/CLI verb must exist, and — the teeth — the set
of on-disk sinks DISCOVERED from ``paths.py`` / ``blackboard.py`` by AST must be accounted for exactly
(documented store or out-of-scope-with-a-reason). A new sink the code grows that the declaration omits
turns this build red.

This guard reads files and imports the generator, which uses ONLY the standard library and imports
NEITHER trust domain — so it is safe in the reads-only ``the briefing explains every agent and
capability`` CI leg (which installs only pytest). It never imports ``framework``.
"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_GEN = _REPO / "docs" / "data-ground-truth" / "gen_data_ground_truth.py"
_DOC = _REPO / "DATA-GROUND-TRUTH.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_data_ground_truth", _GEN)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


g = _load_generator()


# --------------------------------------------------------------------------------------------
# The source of truth is grounded in code, and the document is in sync.
# --------------------------------------------------------------------------------------------
def test_the_document_is_in_sync_with_the_source_of_truth() -> None:
    """The whole check the required CI job runs: grounding holds AND both blocks match. FAILS on a
    tree without this change (no generated blocks, or a table hand-edited away from the code)."""
    problems = g.check()
    assert problems == [], "data-ground-truth drift:\n" + "\n".join(problems)


def test_grounding_holds_and_returns_the_discovered_sinks() -> None:
    """validate() raises on any grounding failure; on success it returns the discovered sink set."""
    discovered = g.validate()
    assert discovered  # non-empty


def test_discovered_sinks_are_exactly_the_expected_set() -> None:
    """Pin the discovered sinks so a code change that adds/removes an on-disk store is LOUD here, not
    silently absorbed. Derived from the code by AST — this states the value discovery landed on."""
    assert g.discover_sinks() == {
        "evidence", ".blackboard", ".evidence-keys", ".entitlement", ".authority", ".authority-root",
        ".memory", ".dryrun", ".improve", ".intake-authorizations.txt",
        ".crucible-v2.log", ".planner-state.json",
    }


def test_every_discovered_sink_is_accounted_for() -> None:
    """The bijection: no discovered sink is undocumented, and no accounted sink is a phantom."""
    src = g.load_source()
    discovered = g.discover_sinks(src)
    documented = {sk for s in src["stores"] for sk in s["sinks"]}
    excluded = {o["sink"] for o in src["out_of_scope"]}
    assert discovered == documented | excluded


def test_cross_check_test_named_by_the_doc_exists() -> None:
    src = g.load_source()
    assert (_REPO / src["cross_check_test"]).is_file()
    assert src["cross_check_test"] in _DOC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------------
# The generation is real, not hardcoded.
# --------------------------------------------------------------------------------------------
def test_generation_is_real_not_hardcoded() -> None:
    """Change a store cell in an in-memory copy; the rendered table must follow (no hand-copied text)."""
    src = copy.deepcopy(g.load_source())
    src["stores"][0]["mutable"] = "TOTALLY-DIFFERENT-SENTINEL-VALUE"
    assert "TOTALLY-DIFFERENT-SENTINEL-VALUE" in g.render_main(src)
    # ...and the real doc does NOT contain the sentinel (proving the committed doc was really generated).
    assert "TOTALLY-DIFFERENT-SENTINEL-VALUE" not in _DOC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------------
# THE TEETH — each failure mode is provoked and must be caught. (AC: negative controls, same run.)
# --------------------------------------------------------------------------------------------
def test_a_new_undocumented_egress_site_turns_the_build_red() -> None:
    """AC: adding a fixture egress site the declaration omits turns CI red. Inject a discovered sink
    that neither a store nor the out-of-scope ledger accounts for — validate() must reject it."""
    src = g.load_source()
    discovered = set(g.discover_sinks(src)) | {".secret-leak"}
    with pytest.raises(g.DriftError, match=r"does not describe"):
        g.validate(src, discovered=discovered)


def test_the_ast_rule_really_discovers_a_new_sink_in_synthetic_code() -> None:
    """The discovery is non-vacuous: a synthetic paths.py-shaped snippet that writes to a NEW hidden
    dir is found by the same AST rule the guard uses in CI."""
    synthetic = (
        "from pathlib import Path\n"
        "def v2_root() -> Path: ...\n"
        "def leak_dir():\n"
        "    return v2_root() / '.secret-leak'\n"
    )
    found = g.sinks_in_text(synthetic)
    assert ".secret-leak" in found
    # A bare join with no engagement/state root is NOT a sink (guards against over-matching).
    assert g.sinks_in_text("x = some_dir() / '.thing'\n") == set()


def test_a_phantom_accounted_sink_no_code_declares_is_rejected() -> None:
    """A sink accounted for in the source of truth but absent from the code turns the build red."""
    src = copy.deepcopy(g.load_source())
    src["stores"][0]["sinks"].append(".no-longer-exists")
    with pytest.raises(g.DriftError, match=r"no code declares"):
        g.validate(src)


def test_a_missing_enforcing_symbol_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    src["stores"][0]["symbols"][0]["symbol"] = "no_such_function_zzz"
    with pytest.raises(g.DriftError, match=r"not defined"):
        g.validate(src)


def test_a_missing_cli_verb_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    src["stores"][0]["cli_verbs"] = ["not-a-real-verb-zzz"]
    with pytest.raises(g.DriftError, match=r"CLI verb"):
        g.validate(src)


def test_a_missing_env_override_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    for s in src["stores"]:
        if s.get("env_overrides"):
            s["env_overrides"][0]["name"] = "CRUCIBLE_NO_SUCH_ENV_ZZZ"
            break
    with pytest.raises(g.DriftError, match=r"env override"):
        g.validate(src)


def test_a_missing_literal_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    for s in src["stores"]:
        if s.get("literals"):
            s["literals"][0]["text"] = "this-literal-appears-in-no-source-zzz"
            break
    with pytest.raises(g.DriftError, match=r"literal"):
        g.validate(src)


def test_an_out_of_scope_entry_without_a_reason_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    src["out_of_scope"][0]["reason"] = "   "
    with pytest.raises(g.DriftError, match=r"no stated reason"):
        g.validate(src)


def test_a_sink_both_documented_and_excluded_is_rejected() -> None:
    src = copy.deepcopy(g.load_source())
    # .memory is out-of-scope; also claim it as documented on the first store -> contradiction.
    src["stores"][0]["sinks"].append(".memory")
    with pytest.raises(g.DriftError, match=r"both documented and out-of-scope"):
        g.validate(src)


# --------------------------------------------------------------------------------------------
# The document-region guard has teeth on the markdown itself.
# --------------------------------------------------------------------------------------------
def test_check_catches_a_drifted_document_block() -> None:
    """A tampered region between the markers must be reported by check()'s region comparison."""
    block = g.render_main()
    good = f"prefix\n{block}\nsuffix"
    assert g._extract_region(good, g.BEGIN, g.END, Path("synthetic")) == block
    tampered = good.replace("HTTP evidence archive", "SOMETHING ELSE")
    assert g._extract_region(tampered, g.BEGIN, g.END, Path("synthetic")) != block


def test_missing_markers_are_reported_not_silently_ignored() -> None:
    with pytest.raises(g.DriftError):
        g._extract_region("a document with no markers", g.BEGIN, g.END, Path("synthetic"))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
