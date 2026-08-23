"""Release gate — the RELEASE-MANIFEST BINDING battery, as an honest scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III) requires that "the release manifest binds suite identity,
test count, skipped tests, commit, environment and JUnit digest — ``tools/verification_manifest.py --check``
already re-derives these from the bound artifact." A verification claim ("1885 passed at <commit>") is only
worth as much as the artifact it is bound to: if ``--check`` trusted the manifest's own summary it would be
checking the number against itself. This board drives the REAL tool end to end — it runs a tiny suite through
``verification_manifest run``, then proves ``check`` re-derives counts + suite identity FROM the bound JUnit
and REJECTS every binding tamper: a hand-edited count, a swapped JUnit digest, a narrowed selection, a skip
that covers a claimed behaviour, a wrong commit, and a failed run.

HOW IT STAYS HONEST (model: ``test_production_invariants.py``). Each row asserts the TRUE bar; a bar not met
is ``@pytest.mark.xfail(strict=True, reason="<slice>")``. Every tamper row is paired with the untampered
happy path — the single non-vacuity control proving ``check`` CAN say OK — so "rejects a tamper" is a real
difference, not a checker that rejects everything. Crucially the happy path asserts the check ran
``artifact-reverified`` (it actually opened the bound JUnit), because a check that silently fell back to
"manifest-internal only" would pass every tamper that leaves the manifest self-consistent.

NO FRAMEWORK IMPORTS — the tool is pure stdlib and the suite it runs is a throwaway one-test file, so this
runs in BOTH legs of the required P5 job and needs no ci.yml offense-leg entry.
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "verification_manifest.py"

# A distinctive term the throwaway suite's SKIP reason carries, so --no-skip-covering can be exercised.
_SKIP_TERM = "SCOREBOARDPROBECHANNEL"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_vigil_verification_manifest_under_test", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


_PROBE_SUITE = (
    "import pytest\n"
    "def test_probe_passes():\n"
    "    assert 1 + 1 == 2\n"
    f"@pytest.mark.skip(reason={_SKIP_TERM!r})\n"
    "def test_probe_skipped():\n"
    "    assert False\n"
)


@pytest.fixture(scope="module")
def manifest(tmp_path_factory):
    """Run the throwaway suite through the REAL tool and return (module, manifest_path, manifest_dict).

    Hermetic: the suite is a one-file, import-free pytest run with cwd inside the tmp dir, so no repo
    conftest/ini is loaded and the manifest describes only this probe."""
    tmp = tmp_path_factory.mktemp("manifest-binding")
    suite = tmp / "test_scoreboard_probe.py"
    suite.write_text(_PROBE_SUITE, encoding="utf-8")
    out = tmp / "verify.json"
    proc = subprocess.run(
        [sys.executable, str(_TOOL), "--out", str(out), "--",
         sys.executable, "-m", "pytest", str(suite), "-p", "no:cacheprovider", "-q"],
        capture_output=True, text=True, cwd=str(tmp),
    )
    assert out.is_file(), f"the manifest tool wrote no manifest: {proc.stderr or proc.stdout}"
    data = json.loads(out.read_text(encoding="utf-8"))
    return _load_tool(), out, data


def _check(mod, manifest_path: Path, **kw) -> tuple[int, str]:
    """Run the tool's ``check`` and capture (exit_code, stdout)."""
    defaults = dict(expect_passed=None, expect_commit=None, allow_dirty=True, max_skipped=None)
    defaults.update(kw)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = mod.check(manifest_path, **defaults)
    return code, buf.getvalue()


def _rewrite(tmp: Path, data: dict, junit_bytes: bytes | None = None) -> Path:
    """Write a (possibly tampered) manifest to a fresh path, pointing junit_path at a COPY so a JUnit tamper
    can be exercised without disturbing the shared fixture's artifact."""
    d = copy.deepcopy(data)
    junit_src = Path(data["junit_path"])
    junit_copy = tmp / "verify.junit.xml"
    junit_copy.write_bytes(junit_bytes if junit_bytes is not None else junit_src.read_bytes())
    d["junit_path"] = str(junit_copy)
    mpath = tmp / "verify.json"
    mpath.write_text(json.dumps(d, indent=2), encoding="utf-8")
    return mpath


# =========================================================================================================
# The suite really ran, and its identity is bound.
# =========================================================================================================
def test_the_manifest_binds_a_real_run(manifest):
    _mod, _path, data = manifest
    assert data["exit_status"] == 0, f"the probe suite did not pass: {data}"
    assert data["counts"] == {"passed": 1, "failed": 0, "error": 0, "skipped": 1, "total": 2}, data["counts"]
    assert data["suite"]["node_count"] == 2 and data["suite"]["node_digest"], data["suite"]
    assert data["junit_sha256"] and Path(data["junit_path"]).is_file(), "the JUnit artifact was not bound"


def test_negative_control_an_untampered_claim_is_artifact_reverified_OK(manifest):
    """The single non-vacuity control: an untampered claim checks OK — AND the check actually opened the
    bound JUnit (``artifact-reverified``), not merely trusted the manifest. Every tamper row below is a real
    difference against this, and none of them can pass by the check silently degrading to manifest-internal."""
    mod, _path, data = manifest
    tmp = _path.parent / "happy"
    tmp.mkdir(exist_ok=True)
    mpath = _rewrite(tmp, data)
    code, out = _check(mod, mpath, expect_passed=1, expect_nodes=2,
                       expect_suite_digest=data["suite"]["node_digest"])
    assert code == 0, f"an untampered claim was rejected: {out}"
    assert "artifact-reverified" in out, (
        f"the check did not re-verify against the bound JUnit artifact (grounding was not artifact-reverified): {out}"
    )


# =========================================================================================================
# Every binding tamper is rejected.
# =========================================================================================================
def test_a_hand_edited_count_is_caught_by_rederivation(manifest, tmp_path):
    """The manifest says ``passed`` is something the bound JUnit does not — ``check`` recomputes from the
    artifact and rejects the mismatch, so the count cannot be edited to a nicer number after the fact."""
    mod, _path, data = manifest
    tampered = copy.deepcopy(data)
    tampered["counts"]["passed"] = 999
    mpath = _rewrite(tmp_path, tampered)
    code, out = _check(mod, mpath)
    assert code == 1 and "do not match the bound JUnit artifact" in out, out


def test_a_swapped_junit_digest_is_caught(manifest, tmp_path):
    """The bound JUnit file is altered but its recorded ``junit_sha256`` is not — the manifest then describes
    a different run than the file it points to, and ``check`` rejects it."""
    mod, _path, data = manifest
    original = Path(data["junit_path"]).read_bytes()
    mpath = _rewrite(tmp_path, data, junit_bytes=original + b"<!-- tampered -->")
    code, out = _check(mod, mpath)
    assert code == 1 and "hashes differently from junit_sha256" in out, out


def test_a_narrowed_selection_is_caught_by_expect_nodes(manifest, tmp_path):
    """A run that quietly dropped tests still reports a green exit and a plausible count; only the node count
    catches it. ``--expect-nodes`` for a different number is rejected."""
    mod, _path, data = manifest
    mpath = _rewrite(tmp_path, data)
    code, out = _check(mod, mpath, expect_nodes=999)
    assert code == 1 and "a narrowed selection can look green" in out, out


def test_a_different_test_SET_is_caught_by_the_suite_digest(manifest, tmp_path):
    mod, _path, data = manifest
    mpath = _rewrite(tmp_path, data)
    code, out = _check(mod, mpath, expect_suite_digest="sha256-of-a-different-suite")
    assert code == 1 and "suite identity differs" in out, out


def test_a_skip_covering_a_claimed_behaviour_is_caught(manifest, tmp_path):
    """"Green with the meaningful half skipped" is the failure this manifest exists to expose:
    ``--no-skip-covering`` names a behaviour that must have RUN, and the check rejects a manifest whose skip
    reasons mention it."""
    mod, _path, data = manifest
    mpath = _rewrite(tmp_path, data)
    code, out = _check(mod, mpath, no_skip_covering=[_SKIP_TERM])
    assert code == 1 and "did not run" in out, out


def test_a_wrong_commit_is_caught(manifest, tmp_path):
    mod, _path, data = manifest
    pinned = copy.deepcopy(data)
    pinned["commit"] = "abcdef1234567890" + "0" * 24
    mpath = _rewrite(tmp_path, pinned)
    ok_code, _ = _check(mod, mpath, expect_commit="abcdef1")
    bad_code, bad_out = _check(mod, mpath, expect_commit="deadbee")
    assert ok_code == 0, "a matching commit pin was wrongly rejected"
    assert bad_code == 1 and "claimed commit" in bad_out, bad_out


def test_a_failed_run_is_never_accepted(manifest, tmp_path):
    """A manifest whose bound run FAILED (non-zero exit) is rejected regardless of any other claim — a
    verification claim over a red run is not a verification."""
    mod, _path, data = manifest
    failed = copy.deepcopy(data)
    failed["exit_status"] = 1
    mpath = _rewrite(tmp_path, failed)
    code, out = _check(mod, mpath)
    assert code == 1 and "the run FAILED" in out, out


def test_negative_control_the_skip_guard_ignores_an_unrelated_term(manifest, tmp_path):
    """Non-vacuity for the skip row: ``--no-skip-covering`` a term that appears in NO skip reason passes —
    proving the guard rejects on a real match, not on any term at all."""
    mod, _path, data = manifest
    mpath = _rewrite(tmp_path, data)
    code, out = _check(mod, mpath, no_skip_covering=["a-behaviour-nothing-skipped-mentions"])
    assert code == 0, f"the skip guard rejected an unrelated term: {out}"


# =========================================================================================================
# The scoreboard itself.
# =========================================================================================================
def test_no_row_is_a_non_strict_xfail():
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
