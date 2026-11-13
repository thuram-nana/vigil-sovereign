"""An engagement slug is ONE path component — enforced where the path is built.

``common.paths`` is the single place a slug becomes a filesystem path: ``target_dir`` (and every helper
derived from it), the ephemeral write base, and ``authority_path``. A slug that carries a separator, a
``.``/``..`` component or a control character used to be joined verbatim, so any caller that forwarded an
unvalidated slug (the console's ``/api/library/<slug>``, ``/api/events?slug=``, ``/api/charter/<slug>``,
``/api/planner/<slug>``, the read API's ``/engagement/<slug>``) addressed files OUTSIDE ``targets/`` and
the authority dir. The refusal lives here so every present and future slug-keyed reader is covered.
"""

from __future__ import annotations

import enum
from pathlib import Path, PurePosixPath

import pytest

from framework.v2.common import paths

HOSTILE = [
    "../../../../outside/other-tenant",   # relative traversal (the /api/library/<slug> form)
    "/abs/outside",                        # absolute right operand: pathlib DROPS the left side
    "..",
    ".",
    "a/b",
    "a/../../b",
    "a\\b",
    "..\\..\\x",
    "nul\x00byte",
    "victim\n",                            # a control char: never a legitimate directory name
    "tab\tbed",
    "del\x7fchar",
]

# What real slugs look like: console-minted (`_slugify` + run id + hex tail), CLI / hand-made target
# dirs (dots, uppercase, underscores — incl. the shipped `_template` scaffold), and long ones.
LEGIT = ["acme", "Acme.Corp_2-prod", "_template", "loopback-20261111T101500.123-0001-a1b2c3d4",
         "a..b", "x" * 120, "ünïcode-kunde", "<proto-killswitch>"]


@pytest.fixture()
def root(tmp_path, monkeypatch):
    r = tmp_path / "cruc"
    (r / "framework" / "v2").mkdir(parents=True)
    (r / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(r))
    monkeypatch.delenv("CRUCIBLE_ROOT_STRICT", raising=False)
    paths._reset_cache()
    yield r
    paths.set_ephemeral_write_root(None)
    paths._reset_cache()


_TARGET_HELPERS = [paths.target_dir, paths.charter_path, paths.charter_draft_path, paths.threat_model_path,
                   paths.attack_tree_path, paths.engagement_log, paths.evidence_archive_dir,
                   paths.crucible_v2_log, paths.planner_state, paths.phase_ledger_path,
                   paths.phase_report_path, paths.endpoints_path, paths.fingerprint_path]


@pytest.mark.parametrize("slug", HOSTILE)
def test_target_dir_family_refuses_a_slug_that_is_not_one_component(root, slug):
    for fn in _TARGET_HELPERS:
        with pytest.raises(ValueError):
            fn(slug)
    with pytest.raises(ValueError):
        paths.evidence_dir(slug, "act-1")


@pytest.mark.parametrize("slug", HOSTILE)
def test_ephemeral_write_base_refuses_a_slug_that_is_not_one_component(root, tmp_path, slug):
    """The ZDR/ephemeral branch joins the slug onto a DIFFERENT base and does not pass through
    ``target_dir`` — it needs the same refusal or the tmpfs base is escapable."""
    paths.set_ephemeral_write_root(tmp_path / "ephemeral")
    for fn in (paths.crucible_v2_log, paths.evidence_archive_dir, paths.phase_ledger_path,
               paths.phase_report_path):
        with pytest.raises(ValueError):
            fn(slug)


@pytest.mark.parametrize("slug", HOSTILE)
def test_authority_path_refuses_a_slug_that_is_not_one_component(root, slug):
    """``authority_path`` does not go through ``target_dir``; it is the helper whose file CONTENT the
    console returns (scope / issuer / window), so it is the worst one to leave open."""
    with pytest.raises(ValueError):
        paths.authority_path(slug)


@pytest.mark.parametrize("slug", LEGIT)
def test_legitimate_slugs_resolve_exactly_as_before(root, tmp_path, slug):
    assert paths.target_dir(slug) == paths.targets_root() / slug
    assert paths.target_dir(slug).parent == paths.targets_root()
    assert paths.charter_path(slug) == paths.targets_root() / slug / "charter.md"
    assert paths.crucible_v2_log(slug) == paths.targets_root() / slug / ".crucible-v2.log"
    assert paths.planner_state(slug) == paths.targets_root() / slug / ".planner-state.json"
    assert paths.authority_path(slug) == paths.authority_dir() / f"{slug}.authority.json"
    assert paths.authority_path(slug).parent == paths.authority_dir()
    paths.set_ephemeral_write_root(tmp_path / "ephemeral")
    assert paths.crucible_v2_log(slug) == tmp_path / "ephemeral" / slug / ".crucible-v2.log"


def test_the_empty_no_engagement_slug_resolves_as_before(root):
    """``""`` is the no-engagement value some callers carry; it is not refused and still names the base."""
    assert paths.target_dir("") == paths.targets_root()
    assert paths.crucible_v2_log("") == paths.targets_root() / ".crucible-v2.log"


# --- the value checked is the value joined -------------------------------------------------------------
# pathlib joins an argument by its os.fspath content, not by str(). Each object below has a benign str()
# but hostile content, so a guard that checks str(slug) and then returns the original object passes it.


class _StrWithBenignStr(str):
    __slots__ = ()

    def __str__(self) -> str:
        return "benign"


class _EnumSlug(str, enum.Enum):
    ESCAPE = "../../../escaped-enum"
    REAL = "acme"


class _PathLikeWithBenignStr:
    def __init__(self, fspath: str) -> None:
        self._fspath = fspath

    def __str__(self) -> str:
        return "benign"

    def __fspath__(self) -> str:
        return self._fspath


_HOSTILE_OBJECTS = [
    pytest.param(_StrWithBenignStr("../../../escaped-sub"), id="str-subclass"),
    pytest.param(_EnumSlug.ESCAPE, id="str-enum"),
    pytest.param(_PathLikeWithBenignStr("../../../escaped"), id="pathlike"),
    pytest.param(PurePosixPath("a/../../b"), id="purepath"),
]


@pytest.mark.parametrize("obj", _HOSTILE_OBJECTS)
def test_a_non_plain_str_slug_is_checked_by_the_content_pathlib_joins(root, tmp_path, obj):
    for fn in _TARGET_HELPERS:
        with pytest.raises(ValueError):
            fn(obj)
    with pytest.raises(ValueError):
        paths.authority_path(obj)
    paths.set_ephemeral_write_root(tmp_path / "ephemeral")
    with pytest.raises(ValueError):
        paths.crucible_v2_log(obj)


@pytest.mark.parametrize("obj, content", [
    pytest.param(_StrWithBenignStr("acme"), "acme", id="str-subclass"),
    pytest.param(_EnumSlug.REAL, "acme", id="str-enum"),
    pytest.param(_PathLikeWithBenignStr("acme"), "acme", id="pathlike"),
    pytest.param(Path("acme"), "acme", id="path"),
])
def test_a_safe_non_plain_str_slug_is_returned_as_the_plain_str_that_was_checked(root, tmp_path, obj, content):
    out = paths._slug_component(obj)
    assert type(out) is str and out == content
    assert paths.target_dir(obj) == paths.targets_root() / content
    assert paths.authority_path(obj) == paths.authority_dir() / f"{content}.authority.json"
    paths.set_ephemeral_write_root(tmp_path / "ephemeral")
    assert paths.crucible_v2_log(obj) == tmp_path / "ephemeral" / content / ".crucible-v2.log"


@pytest.mark.parametrize("slug", LEGIT + [""])
def test_a_plain_str_slug_comes_back_as_an_equal_plain_str(slug):
    out = paths._slug_component(slug)
    assert type(out) is str and out == slug


@pytest.mark.parametrize("bad", [None, 7, b"acme"])
def test_a_value_that_is_not_a_path_is_a_type_error(root, bad):
    with pytest.raises(TypeError):
        paths._slug_component(bad)
    with pytest.raises(TypeError):
        paths.target_dir(bad)
    with pytest.raises(TypeError):
        paths.authority_path(bad)
